use std::time::Duration;

use aos_memory_server::{build_router, build_state, ServerConfig};
use serde_json::{json, Value};

struct TestServer {
    base: String,
    _dir: tempfile::TempDir,
}

fn start_server() -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let config = ServerConfig {
        listen: addr.to_string(),
        store_path: dir.path().join("memory.db"),
        auth_db_path: dir.path().join("auth.db"),
        secrets_dir: dir.path().join("secrets"),
        admin_token: "admin-test".to_string(),
        bridge_token: "bridge-test".to_string(),
        public_url: format!("http://{addr}"),
    };
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let state = build_state(config).unwrap();
            axum::serve(listener, build_router(state)).await.unwrap();
        });
    });

    let base = format!("http://{addr}");
    for _ in 0..100 {
        if ureq::get(&format!("{base}/health")).call().is_ok() {
            return TestServer { base, _dir: dir };
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("test server did not become healthy");
}

fn request(
    server: &TestServer,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: Option<Value>,
) -> (u16, Value) {
    let mut req = ureq::request(method, &format!("{}{}", server.base, path));
    for (name, value) in headers {
        req = req.set(name, value);
    }
    let response = match body {
        Some(body) => req.send_json(body),
        None => req.call(),
    };
    match response {
        Ok(response) => (
            response.status(),
            response.into_json::<Value>().unwrap_or(Value::Null),
        ),
        Err(ureq::Error::Status(status, response)) => (
            status,
            response.into_json::<Value>().unwrap_or(Value::Null),
        ),
        Err(error) => panic!("request failed: {error}"),
    }
}

fn admin() -> Vec<(&'static str, String)> {
    vec![("x-uomp-admin-token", "admin-test".to_string())]
}

fn bridge() -> Vec<(&'static str, String)> {
    vec![("x-uomp-bridge-token", "bridge-test".to_string())]
}

fn bearer(token: &str) -> Vec<(&'static str, String)> {
    vec![("authorization", format!("Bearer {token}"))]
}

fn scopes() -> Value {
    json!({
        "read": { "tags": ["notes"], "keys": [], "denyTags": [], "denyKeys": [] },
        "write": { "tags": [], "keys": ["note.new"], "denyTags": [], "denyKeys": [] }
    })
}

#[test]
fn native_server_auth_consent_memory_staged_payload_audit() {
    let server = start_server();

    let (status, body) = request(&server, "GET", "/health", &[], None);
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");

    let (status, _) = request(&server, "GET", "/v1/memory?tag=notes", &[], None);
    assert_eq!(status, 401);

    let (status, body) = request(
        &server,
        "POST",
        "/v1/sessions",
        &admin(),
        Some(json!({
            "agent_id": "claude",
            "agent_name": "Claude",
            "requested_scopes": scopes(),
            "duration_minutes": 5
        })),
    );
    assert_eq!(status, 200);
    let session_id = body["session_id"].as_str().unwrap().to_string();

    let (status, body) = request(
        &server,
        "POST",
        &format!("/v1/sessions/{session_id}/grant"),
        &admin(),
        Some(json!({ "granted_scopes": scopes() })),
    );
    assert_eq!(status, 200);
    let token = body["token"].as_str().unwrap().to_string();

    let (status, body) = request(
        &server,
        "PUT",
        "/v1/memory/note.new",
        &bearer(&token),
        Some(json!({
            "value": { "body": "hello" },
            "tags": ["notes"],
            "sensitivity": "low",
            "description": "integration test"
        })),
    );
    assert_eq!(status, 200);
    assert_eq!(body["approval_required"], true);
    let staged_id = body["staged_write_id"].as_str().unwrap().to_string();

    let (status, body) = request(&server, "GET", "/v1/staged-writes?status=pending", &admin(), None);
    assert_eq!(status, 200);
    assert!(body["staged_writes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|write| write["id"] == staged_id.as_str()));

    let (status, _) = request(
        &server,
        "POST",
        &format!("/v1/staged-writes/{staged_id}/approve"),
        &admin(),
        Some(json!({ "reviewed_by": "user" })),
    );
    assert_eq!(status, 200);

    let (status, body) = request(&server, "GET", "/v1/memory/note.new", &bearer(&token), None);
    assert_eq!(status, 200);
    assert_eq!(body["item"]["key"], "note.new");

    let (status, body) = request(&server, "GET", "/v1/memory?tag=notes", &bearer(&token), None);
    assert_eq!(status, 200);
    assert!(!body["items"].as_array().unwrap().is_empty());

    let (status, _) = request(&server, "GET", "/v1/memory?tag=private", &bearer(&token), None);
    assert_eq!(status, 403);

    let (status, body) = request(
        &server,
        "POST",
        "/v1/consent/requests",
        &bridge(),
        Some(json!({
            "agent_id": "device-agent",
            "agent_name": "Device Agent",
            "requested_scopes": scopes(),
            "duration_minutes": 5
        })),
    );
    assert_eq!(status, 200);
    assert_eq!(body["approval_required"], true);
    let request_id = body["request_id"].as_str().unwrap().to_string();

    let (status, body) = request(
        &server,
        "GET",
        &format!("/v1/consent/requests/{request_id}/status"),
        &bridge(),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(body["status"], "pending");

    let (status, body) = request(
        &server,
        "GET",
        "/v1/consent/requests?status=pending",
        &admin(),
        None,
    );
    assert_eq!(status, 200);
    assert!(body["requests"]
        .as_array()
        .unwrap()
        .iter()
        .any(|request| request["request_id"] == request_id.as_str()));

    let (status, _) = request(
        &server,
        "POST",
        &format!("/v1/consent/requests/{request_id}/approve"),
        &admin(),
        Some(json!({})),
    );
    assert_eq!(status, 200);

    let (status, body) = request(
        &server,
        "GET",
        &format!("/v1/consent/requests/{request_id}/status"),
        &bridge(),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(body["status"], "approved");
    let consent_token = body["token"].as_str().unwrap().to_string();

    let (status, _) = request(
        &server,
        "GET",
        "/v1/memory?tag=notes",
        &bearer(&consent_token),
        None,
    );
    assert_eq!(status, 200);

    let (status, body) = request(&server, "GET", "/v1/audit?limit=100", &admin(), None);
    assert_eq!(status, 200);
    assert!(body["events"].as_array().unwrap().iter().any(|event| {
        event["action"] == "consent" && event["decision"] == "allow"
    }));

    let (status, body) = request(
        &server,
        "POST",
        "/v1/consent/requests",
        &bridge(),
        Some(json!({
            "agent_id": "denied-agent",
            "requested_scopes": scopes(),
            "duration_minutes": 5
        })),
    );
    assert_eq!(status, 200);
    let denied_id = body["request_id"].as_str().unwrap().to_string();
    let (status, _) = request(
        &server,
        "POST",
        &format!("/v1/consent/requests/{denied_id}/deny"),
        &admin(),
        Some(json!({})),
    );
    assert_eq!(status, 200);
    let (status, body) = request(&server, "GET", "/v1/audit?limit=100", &admin(), None);
    assert_eq!(status, 200);
    assert!(body["events"].as_array().unwrap().iter().any(|event| {
        event["action"] == "consent" && event["decision"] == "deny"
    }));

    let (status, body) = request(
        &server,
        "POST",
        "/v1/payload",
        &bearer(&token),
        Some(json!({
            "ciphertext": "ciphertext-value",
            "encryption": { "alg": "A256GCM", "key_id": "test" },
            "format": "text",
            "size": 16,
            "hash": "abc123"
        })),
    );
    assert_eq!(status, 200);
    let payload_id = body["payload_id"].as_str().unwrap().to_string();

    let (status, body) = request(
        &server,
        "GET",
        &format!("/v1/payload/{payload_id}"),
        &bearer(&token),
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(body["ciphertext"], "ciphertext-value");

    let (status, body) = request(&server, "GET", "/v1/payload", &admin(), None);
    assert_eq!(status, 200);
    assert!(body["payloads"]
        .as_array()
        .unwrap()
        .iter()
        .any(|payload| payload["payload_id"] == payload_id.as_str()));

    let (status, _) = request(
        &server,
        "DELETE",
        &format!("/v1/payload/{payload_id}"),
        &admin(),
        None,
    );
    assert_eq!(status, 200);

    let (status, body) = request(&server, "GET", "/v1/audit?limit=100", &admin(), None);
    assert_eq!(status, 200);
    let events = body["events"].as_array().unwrap();
    assert!(events
        .iter()
        .any(|event| event["action"] == "read" && event["decision"] == "allow"));
    assert!(events
        .iter()
        .any(|event| event["action"] == "read" && event["decision"] == "deny"));

    let (status, _) = request(
        &server,
        "POST",
        &format!("/v1/sessions/{session_id}/revoke"),
        &admin(),
        Some(json!({})),
    );
    assert_eq!(status, 200);

    let (status, _) = request(&server, "GET", "/v1/memory/note.new", &bearer(&token), None);
    assert_eq!(status, 401);

    let (status, body) = request(&server, "GET", "/v1/audit?limit=100", &admin(), None);
    assert_eq!(status, 200);
    assert!(body["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| event["action"] == "revoke" && event["decision"] == "allow"));
}

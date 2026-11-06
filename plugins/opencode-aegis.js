// Aegis OS OpenCode plugin (V1 `server` hooks + V2 `setup` placeholder).
// The plugin only talks to the per-session broker over AOS_CONTROL_SOCKET; it does not
// implement policy itself. Outside `aos run` it is inert.

import net from "node:net";

function brokerRequest(method, path, payload, timeoutMs = 5000) {
  const socketPath = process.env.AOS_CONTROL_SOCKET;
  const token = process.env.AOS_SESSION_TOKEN;
  if (!socketPath || !token) {
    return Promise.reject(new Error("Aegis broker is not available in this session"));
  }
  const body = payload === undefined ? "" : JSON.stringify(payload);
  const request =
    `${method} ${path} HTTP/1.1\r\n` +
    "Host: aegis-session-broker\r\n" +
    `X-Aegis-Token: ${token}\r\n` +
    "Content-Type: application/json\r\n" +
    `Content-Length: ${Buffer.byteLength(body)}\r\n` +
    "Connection: close\r\n\r\n" +
    body;

  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath, () => socket.write(request));
    const chunks = [];
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };
    socket.setTimeout(timeoutMs, () => fail(new Error("Aegis broker request timed out")));
    socket.on("data", (chunk) => chunks.push(chunk));
    socket.on("error", fail);
    socket.on("end", () => {
      if (settled) return;
      settled = true;
      const data = Buffer.concat(chunks).toString("utf8");
      const split = data.indexOf("\r\n\r\n");
      if (split < 0) return reject(new Error("malformed Aegis broker response"));
      const head = data.slice(0, split);
      const bodyText = data.slice(split + 4);
      let parsed = null;
      try {
        parsed = JSON.parse(bodyText);
      } catch {
        return reject(new Error(`Aegis broker returned non-JSON: ${bodyText.slice(0, 200)}`));
      }
      if (!head.includes(" 200 ")) {
        return reject(new Error(parsed?.error || `Aegis broker returned ${head.split("\r\n")[0]}`));
      }
      resolve(parsed);
    });
  });
}

function decisionError(decision) {
  const reason =
    decision?.reason ||
    decision?.suggested_lease_scope ||
    "Aegis policy requires human approval";
  return new Error(`[Aegis ${decision?.effect || "deny"}] ${reason}`);
}

export default {
  id: "heurion.aegis",

  // OpenCode V1 loader.
  async server() {
    if (!process.env.AOS_CONTROL_SOCKET) return {};
    return {
      "tool.execute.before": async (event, output) => {
        const decision = await brokerRequest("POST", "/v1/adapter/evaluate", {
          tool: event.tool,
          input: output.args ?? {},
        });
        if (decision.effect === "deny" || decision.effect === "ask") {
          throw decisionError(decision);
        }
      },

      "tool.execute.after": async (event, output) => {
        try {
          await brokerRequest("POST", "/v1/adapter/effect", {
            tool: event.tool,
            input: output?.args ?? event?.args ?? {},
            effect: "observed",
            output: { title: output?.title ?? "" },
          });
        } catch {
          // Effect telemetry must never break a tool that already completed.
        }
      },

      "permission.ask": async (input, output) => {
        try {
          const decision = await brokerRequest("POST", "/v1/adapter/evaluate", {
            tool: input?.type ?? "permission",
            input,
          });
          if (decision.effect === "deny" || decision.effect === "ask") {
            output.status = decision.effect;
          }
        } catch {
          // Fall back to OpenCode's native permission decision.
        }
      },

      "shell.env": async (_input, output) => {
        if (process.env.AOS_CONTROL_SOCKET) {
          output.env.AOS_CONTROL_SOCKET = process.env.AOS_CONTROL_SOCKET;
          output.env.AOS_SESSION_TOKEN = process.env.AOS_SESSION_TOKEN ?? "";
          output.env.AOS_ENFORCEMENT = process.env.AOS_ENFORCEMENT ?? "";
        }
      },
    };
  },

  // OpenCode V2 loader currently has no tool hooks; keep the plugin loadable and let the
  // V1 `server` hooks do the work on versions that expose them.
  async setup() {},
};

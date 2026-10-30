# MCP client example

This manifest is for Claude Desktop, Cursor, OpenCode, or any other MCP client. It requests no scopes by default; grant tags explicitly with `--scope`.

## One-time setup

```bash
uomp setup claude --vault ~/Obsidian/MyVault
```

`uomp setup` imports the vault, starts the local server in the background, and writes the UOMP entry into the client config. It does **not** grant access. Restart the client, then ask it to list notes under `notes/projects`.

The first tool call requests `notes/projects`; UOMP opens a local approval page. Approve it and the same request continues. If the page does not open, use `uomp pending` and `uomp approve <request-id>`; `uomp deny <request-id>` closes the request without granting access.

Use `uomp setup cursor` or `uomp setup opencode` for the other clients. `uomp status` shows the server and sessions; `uomp stop` stops the server; `uomp disconnect <client>` removes the config entry and revokes the session.

## Advanced: pre-authorize

`uomp connect` skips the approval page and creates a session immediately:

```bash
uomp connect claude --vault ~/Obsidian/MyVault --scope notes/projects
```

Use this for scripts/CI or when you explicitly want to choose the scope before the agent runs.

## Manual setup

For an unsupported client, or to edit the config yourself:

```bash
# Terminal 1
uomp serve

# Terminal 2
uomp authorize \
  --scope notes/projects \
  --output ~/.uomp/mcp-client.env \
  --no-server

uomp mcp --session ~/.uomp/mcp-client.env --print-config --client claude
```

Paste the generated JSON into the client's `mcpServers` entry. Use `--client cursor` or `--client opencode` for those shapes; without `--client`, the output is the generic `mcpServers` shape.

Tools:

- `list_memory` — keys and metadata for a tag.
- `search_memory` — keys and metadata matching text within a tag.
- `read_memory` — full item content for one key.

Re-running `uomp authorize` to the same `--output` file updates the token; the MCP server re-reads the file before each tool call.

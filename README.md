# packmate-mcp

MCP server that exposes [Packmate](https://gitlab.com/packmate/Packmate) — a CTF network traffic analyzer — to LLM tooling like Claude Desktop or Claude Code.

## Features

- 16 tools across services, patterns, streams, packets, and pcap-file lifecycle.
- Packet content formatting tuned for LLM consumption: `transcript` (auto text/hex with `client→server` markers), `text`, `hex`, `python_bytes`, `base64`.
- Three-layer trimming (per-packet, total budget, packet count) to keep responses inside the LLM context window.
- Pure async `httpx` client over Packmate's HTTP API + Basic Auth.
- stdio transport — drop into Claude Desktop or Claude Code as a subprocess.

## Install

```bash
uvx packmate-mcp        # ephemeral, recommended
# or
pip install packmate-mcp
```

## Configure

All settings are env vars with the `PACKMATE_MCP_` prefix:

| Env var | Default | Description |
|---|---|---|
| `PACKMATE_MCP_BASE_URL` | `http://localhost:65000` | Packmate base URL |
| `PACKMATE_MCP_LOGIN` | (required) | Basic auth login |
| `PACKMATE_MCP_PASSWORD` | (required) | Basic auth password |
| `PACKMATE_MCP_TIMEOUT_SECONDS` | `30` | HTTP request timeout |
| `PACKMATE_MCP_LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` |

See [`.env.example`](.env.example) for a starter template.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%AppData%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "packmate": {
      "command": "uvx",
      "args": ["packmate-mcp"],
      "env": {
        "PACKMATE_MCP_BASE_URL": "http://localhost:65000",
        "PACKMATE_MCP_LOGIN": "BinaryBears",
        "PACKMATE_MCP_PASSWORD": "..."
      }
    }
  }
}
```

Restart Claude Desktop fully (`Cmd+Q` / tray → Quit), then look for the connector under the `+` menu.

### Claude Code

```bash
claude mcp add packmate uvx packmate-mcp \
  --env PACKMATE_MCP_LOGIN=BinaryBears \
  --env PACKMATE_MCP_PASSWORD=...
```

## Tools

See [the design spec](docs/superpowers/specs/2026-05-13-packmate-mcp-design.md) for the full list. Highlights:

- **`get_stream(stream_id, content_format='transcript')`** — fetch a stream with packets pre-rendered. Most common entrypoint.
- **`create_pattern` + `pattern_lookback` + `list_streams(pattern_id=…)`** — the native Packmate workflow for content search.
- **`set_stream_favorite(stream_id, favorite=True/False)`** — pin interesting streams.
- **`pcap_status` / `pcap_start`** — kick off pcap-file processing in FILE mode.

## Development

```bash
git clone https://github.com/umbra2728/packmate-mcp
cd packmate-mcp
uv sync --dev
uv run pytest
uv run ruff check src tests
uv run mypy src
```

Manual smoke test against a real Packmate instance:

```bash
# in the Packmate repo
docker compose up -d
# back here
PACKMATE_MCP_LOGIN=BinaryBears PACKMATE_MCP_PASSWORD=123456 \
  uv run mcp dev src/packmate_mcp/server.py
```

This opens the MCP Inspector and lets you exercise each tool.

## Releasing

This package ships to PyPI via Trusted Publishing. The workflow runs on any `v*.*.*` tag.

1. Bump `version` in `pyproject.toml`.
2. Add a `## [X.Y.Z] - YYYY-MM-DD` section to `CHANGELOG.md`.
3. Commit, tag, push:

```bash
git commit -am "Release vX.Y.Z"
git tag vX.Y.Z
git push --tags
```

One-time setup (not in repo state):

- On PyPI → Account settings → Add a pending publisher with repo `umbra2728/packmate-mcp`, workflow `release.yml`, environment `pypi`.
- On GitHub → repo → Settings → Environments → create `pypi`.

## Related

- [firegex-mcp](https://github.com/umbra2728/firegex-mcp) — sibling MCP server for [Firegex](https://github.com/Pwnzer0tt1/firegex) (PCRE2 regex / proxy WAF).
- [ad-ctf-toolkit](https://github.com/umbra2728/ad-ctf-toolkit) — Claude Code plugin that combines `packmate-mcp` and `firegex-mcp` with skills and sub-agents for Attack/Defense CTF rounds.

## License

MIT — see [LICENSE](LICENSE).

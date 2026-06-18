#!/usr/bin/env bash
# Expose the local server over HTTPS for custom-connector testing and print
# exactly what to paste into Claude's and ChatGPT's connector forms.
# Prefers cloudflared (no account needed for quick tunnels); falls back to ngrok.
set -euo pipefail

PORT="${PORT:-8080}"

print_instructions() {
  local url="$1"
  cat <<EOF

============================================================
 Tunnel up: $url
============================================================

1) Restart the server so OAuth metadata advertises the public URL:

     RESOURCE_SERVER_URL=$url/mcp make dev

2) Claude (Settings -> Connectors -> Add custom connector):

     Name:                Murray Context Ledger
     Remote MCP server URL: $url/mcp

   Leave OAuth client ID/secret empty - Claude discovers Auth0 via the
   server's protected-resource metadata and registers itself (DCR).

3) ChatGPT (Settings -> Apps & Connectors -> Advanced -> enable
   Developer mode, then Create connector):

     Name:           Murray Context Ledger
     MCP server URL: $url/mcp
     Authentication: OAuth

4) Connect, complete the Auth0 login + consent, then ask:
     "What do you know about me from my ledger?"

   Auth0 prerequisites (DCR, API audience, default audience) are in
   docs/CONNECT.md.
============================================================

EOF
}

if command -v cloudflared >/dev/null 2>&1; then
  echo "Starting cloudflared quick tunnel for http://localhost:$PORT ..."
  cloudflared tunnel --url "http://localhost:$PORT" --no-autoupdate 2>&1 | while IFS= read -r line; do
    echo "$line"
    if [[ "$line" =~ (https://[a-zA-Z0-9-]+\.trycloudflare\.com) ]]; then
      print_instructions "${BASH_REMATCH[1]}"
    fi
  done
elif command -v ngrok >/dev/null 2>&1; then
  echo "cloudflared not found; using ngrok. Read the https URL from the ngrok UI below,"
  echo "then follow the same steps printed in docs/CONNECT.md."
  ngrok http "$PORT"
else
  echo "Neither cloudflared nor ngrok is installed." >&2
  echo "  cloudflared: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/" >&2
  echo "  ngrok:       https://ngrok.com/download" >&2
  exit 1
fi

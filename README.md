# Coding Agent Network Logger

A Docker-based network inspection system for logging and analyzing all network connections made by AI coding agents (Claude Code). Uses a Go MITM proxy for HTTP/HTTPS inspection and tcpdump for full packet capture.

## Security Model

- **Trusted Computing Base**: The proxy container handles all logging and packet capture
- **Untrusted**: The coding agent container is treated as potentially malicious and cannot tamper with logs
- **Isolation**: Agent container has read-only access to the CA certificate only

## Quick Start

```bash
# Start everything (proxy + agent with test task)
ANTHROPIC_API_KEY=your-api-key docker compose up

# View the web UI
open http://localhost:8888
```

The default test prompt creates a website that shows the weather from a random city every 2 seconds. Generated files are saved to `./output/`.

## Custom Prompts

```bash
AGENT_PROMPT="Create a simple todo app" docker compose up
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Host Machine                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Web Browser │  │ ./logs/     │  │ ~/.claude/ (auth)   │ │
│  │ :8888       │  │ (logs,pcap) │  │ (read-write mount)  │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
└─────────┼────────────────┼─────────────────────┼────────────┘
          │                │                     │
┌─────────┼────────────────┼─────────────────────┼────────────┐
│ Docker  │                │                     │            │
│  ┌──────▼──────────────────────────────────────┼──────────┐ │
│  │ Proxy Container (TRUSTED)                   │          │ │
│  │  • Go MITM Proxy (:8080)                    │          │ │
│  │  • Web UI (:8888)                           │          │ │
│  │  • tcpdump (packet capture)                 │          │ │
│  │  • Writes to /logs                          │          │ │
│  └──────▲──────────────────────────────────────┼──────────┘ │
│         │                                      │            │
│  ┌──────┴──────────────────────────────────────▼──────────┐ │
│  │ Agent Container (UNTRUSTED)                            │ │
│  │  • Claude Code CLI                                     │ │
│  │  • Routes traffic through proxy                        │ │
│  │  • CA cert installed (read-only)                       │ │
│  │  • No access to logs                                   │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
├── proxy/                  # Go proxy source code
│   ├── main.go            # Proxy server + web UI
│   ├── ca.go              # CA certificate generation
│   ├── logger.go          # Request logging
│   ├── web.go             # Web UI handlers
│   └── static/index.html  # Web UI frontend
├── docker/
│   ├── Dockerfile.proxy   # Trusted proxy container
│   ├── Dockerfile.agent   # Untrusted agent container
│   └── entrypoint.sh      # Agent startup script
├── docker-compose.yml
├── logs/                   # Created at runtime
│   ├── requests.jsonl     # HTTP request logs
│   ├── *.pcap            # Packet captures
│   ├── ca.crt            # CA certificate
│   └── ca.key            # CA private key
└── output/                # Agent-generated files
```

## What Gets Logged

### HTTP/HTTPS Requests (requests.jsonl)

Each request is logged as a JSON line:
```json
{
  "id": "abc123",
  "timestamp": "2026-01-06T10:30:00Z",
  "method": "POST",
  "domain": "api.anthropic.com",
  "path": "/v1/messages",
  "headers": {"Authorization": "[REDACTED]", "Content-Type": "application/json"},
  "pcap_file": "capture_20260106_103000.pcap"
}
```

Sensitive headers (Authorization, API keys) are automatically redacted.

### Packet Capture (*.pcap)

Full packet capture of all network traffic from the agent container, saved in PCAP format. Can be analyzed with Wireshark or tcpdump.

## Web UI

The web UI at http://localhost:8888 provides:
- List of all HTTP/HTTPS requests (newest first)
- Click to expand and see full headers
- Download PCAP files for detailed analysis
- Auto-refresh every 5 seconds

## Running Interactively

To run the proxy separately and interact with the agent:

```bash
# Start just the proxy
docker compose up -d proxy

# Run agent with a custom prompt
docker compose run --rm agent

# Or override the prompt
docker compose run --rm -e AGENT_PROMPT="Your prompt here" agent
```

## Viewing PCAP Files

```bash
# List captured files
ls -la ./logs/*.pcap

# View with tcpdump
tcpdump -r ./logs/capture_*.pcap

# Open in Wireshark
wireshark ./logs/capture_*.pcap
```

## Requirements

- Docker and Docker Compose
- Anthropic API key (passed via `ANTHROPIC_API_KEY` environment variable)

## Troubleshooting

### CA Certificate Issues

If you see SSL errors, the CA certificate may not be properly installed. Check:
```bash
docker compose logs agent
```

### Proxy Not Accessible

Ensure the proxy container is running:
```bash
docker compose ps
docker compose logs proxy
```

### No Requests Logged

Verify traffic is routing through the proxy:
```bash
# Check proxy logs
docker compose logs -f proxy
```

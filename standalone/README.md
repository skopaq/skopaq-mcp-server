# Skopaq MCP Server - Standalone

Self-hosted version of the Skopaq MCP Server for air-gap and enterprise deployments.

## Overview

This is a standalone Node.js version of the Skopaq MCP Server that can run in any environment without depending on Cloudflare Workers. It provides the same MCP (Model Context Protocol) capabilities for AI coding assistants.

**Key Features:**
- Full MCP protocol support (SSE transport)
- Works with Claude Code, Cursor, Windsurf, and other MCP clients
- Uses MinIO for screenshot storage (instead of Cloudflare R2)
- Uses Redis for session state (instead of Durable Objects)
- Docker-ready for Kubernetes deployment

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Start all services (MCP server, MinIO, Redis)
docker-compose up -d

# Check health
curl http://localhost:3000/health

# View logs
docker-compose logs -f argus-mcp
```

### Manual Setup

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Or build and run production
npm run build
npm start
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `HOST` | `0.0.0.0` | Server host |
| `ARGUS_BRAIN_URL` | `http://localhost:8000` | Skopaq Brain API URL |
| `API_TOKEN` | - | API token for Brain authentication |
| `STORAGE_PROVIDER` | `minio` | Storage backend: `minio`, `s3`, `local` |
| `MINIO_ENDPOINT` | `localhost:9000` | MinIO/S3 endpoint |
| `MINIO_ACCESS_KEY` | `minioadmin` | Access key |
| `MINIO_SECRET_KEY` | `minioadmin` | Secret key |
| `MINIO_BUCKET` | `argus-artifacts` | Bucket name |
| `MINIO_SECURE` | `false` | Use HTTPS |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `JWT_SECRET` | - | JWT secret for signed URLs |
| `LOG_LEVEL` | `info` | Logging level |

## Connecting AI Assistants

### Claude Code

Add to your Claude Code MCP configuration (`~/.claude/mcp.json`):

```json
{
  "mcpServers": {
    "argus": {
      "command": "curl",
      "args": ["-N", "http://localhost:3000/sse"],
      "env": {}
    }
  }
}
```

Or use the SSE URL directly:
```
http://localhost:3000/sse
```

### Cursor / Windsurf

Configure the MCP server URL in your IDE settings:
```
http://localhost:3000/sse
```

## Available Tools

| Tool | Description |
|------|-------------|
| `argus_health` | Check Skopaq API health |
| `argus_discover` | Discover page elements |
| `argus_act` | Execute browser actions |
| `argus_test` | Run E2E tests |
| `argus_agent` | Autonomous task completion |
| `argus_extract` | Extract structured data |
| `argus_generate_test` | Generate tests from NL |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AI IDE (Claude/Cursor)                │
│                                                          │
└──────────────────────┬───────────────────────────────────┘
                       │ MCP Protocol (SSE)
                       ▼
┌─────────────────────────────────────────────────────────┐
│              Skopaq MCP Server (Standalone)              │
│                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   Express   │  │   Storage   │  │   Session   │     │
│  │   Server    │  │   (MinIO)   │  │   (Redis)   │     │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘     │
│         │                 │                 │           │
└─────────┼─────────────────┼─────────────────┼───────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────┐  ┌─────────────┐  ┌─────────────┐
│  Skopaq Brain    │  │    MinIO    │  │    Redis    │
│  (FastAPI)      │  │   Bucket    │  │   Session   │
└─────────────────┘  └─────────────┘  └─────────────┘
```

## Kubernetes Deployment

See the Helm chart in `../helm/argus-mcp` for Kubernetes deployment.

```bash
helm install argus-mcp ./helm/argus-mcp \
  --set brain.url=http://argus-brain:8000 \
  --set minio.endpoint=minio:9000
```

## Development

```bash
# Run with hot reload
npm run dev

# Type check
npm run typecheck

# Build
npm run build
```

## Health Check

```bash
curl http://localhost:3000/health
```

Response:
```json
{
  "status": "healthy",
  "storage": { "healthy": true },
  "sessions": { "healthy": true },
  "timestamp": "2026-01-30T12:00:00.000Z"
}
```

## License

MIT - Skopaq E2E Testing Agent

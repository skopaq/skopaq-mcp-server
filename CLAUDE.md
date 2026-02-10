# Skopaq MCP Server

Model Context Protocol (MCP) server that exposes Skopaq E2E testing capabilities to AI coding assistants.

## Project Overview

This is a Cloudflare Workers application that implements the MCP protocol, allowing AI IDEs like Claude Code, Cursor, and Windsurf to interact with Skopaq testing capabilities.

## Tech Stack

- **Runtime**: Cloudflare Workers
- **Language**: TypeScript
- **MCP SDK**: @modelcontextprotocol/sdk
- **Validation**: Zod
- **Build Tool**: Wrangler

## Project Structure

```
argus-mcp-server/
├── src/
│   └── index.ts          # Main MCP server implementation
├── package.json          # Dependencies
├── tsconfig.json         # TypeScript config
├── wrangler.toml         # Cloudflare Workers config
└── worker-configuration.d.ts  # Generated Worker types
```

## MCP Tools Provided

| Tool | Description |
|------|-------------|
| `argus_health` | Check Skopaq API status |
| `argus_discover` | Discover interactive elements on a page |
| `argus_act` | Execute browser actions (click, type, navigate) |
| `argus_test` | Run multi-step E2E tests with screenshots |
| `argus_extract` | Extract structured data from pages |
| `argus_agent` | Autonomous task completion |
| `argus_generate_test` | Generate test steps from natural language |

## Development Commands

```bash
# Install dependencies
npm install

# Local development
npm run dev

# Deploy to Cloudflare Workers
npm run deploy

# Type check
npx tsc --noEmit
```

## Environment Variables (wrangler.toml)

- `ARGUS_API_URL`: Browser automation worker URL
- `ARGUS_BRAIN_URL`: AI brain service URL

## Architecture

```
AI IDE (Claude/Cursor)
    │ MCP Protocol (SSE)
    ▼
Skopaq MCP Server (Cloudflare Workers)
    │ REST API
    ▼
Skopaq API Worker → Browser Automation
```

## Coding Guidelines

1. **TypeScript**: Use strict typing, define interfaces for all API responses
2. **Zod Schemas**: Define input schemas for all MCP tools
3. **Error Handling**: Always handle API errors gracefully with informative messages
4. **Logging**: Use structured logging for debugging

## Release Process

This repo uses semantic-release with release-please:
- `feat:` commits trigger minor version bump
- `fix:` commits trigger patch version bump
- Releases auto-deploy to Cloudflare Workers

## Related Repositories

- [argus-backend](https://github.com/RaphaEnterprises-AI/argus-backend) - Main Skopaq backend
- [argus](https://github.com/RaphaEnterprises-AI/argus) - Skopaq dashboard

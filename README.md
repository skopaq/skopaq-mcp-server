# Skopaq MCP Server

[![Release](https://img.shields.io/github/v/release/RaphaEnterprises-AI/argus-mcp-server)](https://github.com/RaphaEnterprises-AI/argus-mcp-server/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Model Context Protocol (MCP) server for Skopaq E2E Testing Agent. This allows AI coding assistants to interact with Skopaq testing capabilities directly from your IDE.

## Supported AI IDEs

- **Claude Code** - Anthropic's CLI for Claude
- **Cursor** - AI-first code editor
- **Windsurf** - Codeium's AI IDE
- **VS Code** - With MCP extension
- **Any MCP-compatible client**

## Available Tools (74 Total)

### Authentication (4 tools)

| Tool | Description |
|------|-------------|
| `argus_auth` | Start OAuth2 device flow authentication |
| `argus_auth_complete` | Complete OAuth2 device flow after sign-in |
| `argus_auth_status` | Check current authentication status |
| `argus_auth_logout` | Sign out and clear stored credentials |

### Core Browser Testing (4 tools)

| Tool | Description |
|------|-------------|
| `argus_health` | Check Skopaq API status |
| `argus_discover` | Discover interactive elements on a page |
| `argus_act` | Execute browser actions (click, type, navigate) |
| `argus_test` | Run multi-step E2E tests with screenshots |

### Data Extraction & AI Agent (3 tools)

| Tool | Description |
|------|-------------|
| `argus_extract` | Extract structured data from pages |
| `argus_agent` | Autonomous task completion on websites |
| `argus_generate_test` | Generate test steps from natural language |

### Quality Intelligence (3 tools)

| Tool | Description |
|------|-------------|
| `argus_quality_score` | Get overall project quality score (0-100) |
| `argus_quality_stats` | Get detailed quality statistics |
| `argus_risk_scores` | Calculate/retrieve risk scores for components |

### Production Events & Analysis (3 tools)

| Tool | Description |
|------|-------------|
| `argus_events` | List production errors/events with filtering |
| `argus_event_triage` | AI-powered triage recommendations for events |
| `argus_test_from_event` | Generate E2E test from production error |

### Test Management (3 tools)

| Tool | Description |
|------|-------------|
| `argus_tests` | List generated tests by status |
| `argus_test_review` | Review (approve/reject/modify) generated tests |
| `argus_batch_generate` | Generate tests for multiple events at once |

### Self-Healing (4 tools)

| Tool | Description |
|------|-------------|
| `argus_healing_config` | View/update self-healing configuration |
| `argus_healing_patterns` | View learned self-healing patterns with confidence scores |
| `argus_healing_stats` | Get self-healing statistics (success rates, patterns) |
| `argus_healing_review` | Approve/reject healing suggestions |

### Synchronization (4 tools)

| Tool | Description |
|------|-------------|
| `argus_sync_push` | Push local test changes to cloud |
| `argus_sync_pull` | Pull test updates from cloud |
| `argus_sync_status` | Check sync status and conflicts |
| `argus_sync_resolve` | Resolve synchronization conflicts |

### Test Export & Recording (4 tools)

| Tool | Description |
|------|-------------|
| `argus_export` | Export test to code (Python/TS/Java/C#/Ruby/Go) |
| `argus_export_languages` | List supported export languages/frameworks |
| `argus_recording_to_test` | Convert browser recording (rrweb) to test |
| `argus_recording_snippet` | Generate JavaScript snippet for recording sessions |

### Collaboration (2 tools)

| Tool | Description |
|------|-------------|
| `argus_presence` | Get/update user presence in workspace |
| `argus_comments` | Get/add/reply to test comments |

### Project Management (4 tools)

| Tool | Description |
|------|-------------|
| `argus_projects` | List projects user has access to |
| `argus_what_to_test` | Get AI recommendations on what to test next |
| `argus_coverage_gaps` | Identify areas with production errors but no tests |
| `argus_dashboard` | Get comprehensive project dashboard/overview |

### Infrastructure & Monitoring (5 tools)

| Tool | Description |
|------|-------------|
| `argus_infra_overview` | Get infrastructure costs and Selenium Grid status |
| `argus_infra_recommendations` | Get AI recommendations for cost optimization |
| `argus_infra_apply` | Apply infrastructure optimization recommendation |
| `argus_browser_pool` | Get Selenium Grid browser pool real-time status |
| `argus_llm_usage` | Get LLM/AI model usage and costs |

### AI Assistant (1 tool)

| Tool | Description |
|------|-------------|
| `argus_ask` | Ask AI questions about your tests/errors/strategy |

### CI/CD Integration (4 tools) 🆕

| Tool | Description |
|------|-------------|
| `argus_cicd_test_impact` | AI-powered test impact analysis for PRs - 10x faster CI |
| `argus_cicd_deployment_risk` | Risk assessment before deployments |
| `argus_cicd_builds` | List build history |
| `argus_cicd_pipelines` | View CI/CD pipeline status |

### Discovery & Intelligent Crawling (4 tools) 🆕

| Tool | Description |
|------|-------------|
| `argus_discovery_start` | Start autonomous app crawling session |
| `argus_discovery_flows` | Get AI-discovered user flows |
| `argus_discovery_generate` | Generate tests from discovered flows |
| `argus_discovery_compare` | Compare discovery sessions |

### Time Travel Debugging (5 tools) 🆕

| Tool | Description |
|------|-------------|
| `argus_time_travel_checkpoints` | List state checkpoints for test runs |
| `argus_time_travel_history` | View state change history for a thread |
| `argus_time_travel_replay` | Replay execution from a checkpoint |
| `argus_time_travel_fork` | Fork execution for A/B testing |
| `argus_time_travel_compare` | Compare divergent execution paths |

### Visual AI Testing (5 tools) 🆕

| Tool | Description |
|------|-------------|
| `argus_visual_capture` | Capture screenshot with metadata |
| `argus_visual_compare` | AI-powered visual diff between screenshots |
| `argus_visual_baseline` | Set a visual baseline |
| `argus_visual_baselines` | List visual baselines |
| `argus_visual_analyze` | Analyze visual changes with WCAG accessibility |

### Scheduling & Automation (4 tools) 🆕

| Tool | Description |
|------|-------------|
| `argus_schedule_create` | Create a test schedule (cron-style) |
| `argus_schedule_list` | List schedules |
| `argus_schedule_run` | Manually trigger a schedule |
| `argus_schedule_history` | View run history for a schedule |

### Correlation & Analytics (4 tools) 🆕

| Tool | Description |
|------|-------------|
| `argus_correlations_timeline` | View unified SDLC event timeline |
| `argus_correlations_root_cause` | AI-powered root cause analysis |
| `argus_correlations_insights` | Get AI-generated insights |
| `argus_correlations_query` | Natural language queries for correlations |

### API Testing (3 tools) 🆕

| Tool | Description |
|------|-------------|
| `argus_api_discover` | Discover API endpoints from OpenAPI/Swagger |
| `argus_api_generate` | Generate API test cases with AI |
| `argus_api_run` | Execute API tests |

## Installation

### For Claude Code / Claude Desktop

Add to your MCP settings (`~/.claude/claude_desktop_config.json` or Claude Code settings):

```json
{
  "mcpServers": {
    "argus": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://argus-mcp.samuelvinay-kumar.workers.dev/sse"]
    }
  }
}
```

### For Cursor

Add to Cursor's MCP settings:

```json
{
  "mcpServers": {
    "argus": {
      "url": "https://argus-mcp.samuelvinay-kumar.workers.dev/sse"
    }
  }
}
```

## Usage Examples

### Discover Page Elements
```
Use argus_discover to analyze https://example.com and find all interactive elements
```

### Run E2E Test
```
Use argus_test to test login on https://uitestingplayground.com/sampleapp with these steps:
1. Type "TestUser" in the username field
2. Type "pwd" in the password field
3. Click the Log In button
4. Verify the welcome message appears
```

### AI-Powered Test Impact Analysis
```
Use argus_cicd_test_impact to analyze which tests need to run for my PR changes
```

### Autonomous App Discovery
```
Use argus_discovery_start to crawl https://myapp.com and discover all user flows
```

### Visual Regression Testing
```
Use argus_visual_compare to compare the current homepage against the baseline
```

### Time Travel Debugging
```
Use argus_time_travel_checkpoints to list all state snapshots for the failed test run
```

### Root Cause Analysis
```
Use argus_correlations_root_cause to analyze why the checkout test started failing
```

### API Testing
```
Use argus_api_discover to find all endpoints from our OpenAPI spec, then generate tests
```

## Development

### Prerequisites

- Node.js 18+
- Wrangler CLI

### Setup

```bash
cd argus-mcp-server
npm install
```

### Local Development

```bash
npm run dev
```

### Deploy

```bash
npm run deploy
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AI IDE (Claude/Cursor)                    │
└─────────────────────────┬───────────────────────────────────┘
                          │ MCP Protocol (SSE)
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   Skopaq MCP Server                           │
│              (Cloudflare Workers + Durable Objects)          │
│                                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │  74 MCP  │ │   OAuth  │ │    R2    │ │   KV     │       │
│  │  Tools   │ │  Auth    │ │ Storage  │ │  State   │       │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘       │
└───────┼────────────┼────────────┼────────────┼──────────────┘
        │            │            │            │
        └────────────┴────────────┴────────────┘
                          │ REST API
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                     Skopaq Backend                            │
│                                                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │ Browser    │  │ AI Brain   │  │ Knowledge  │            │
│  │ Pool (K8s) │  │ (Railway)  │  │ Graph      │            │
│  └────────────┘  └────────────┘  └────────────┘            │
└─────────────────────────────────────────────────────────────┘
```

## Features

### Self-Healing Selectors
AI-powered selector recovery when elements change

### Smart Waits
Intelligent element detection without explicit waits

### Visual AI Testing
Screenshot comparison with WCAG accessibility analysis

### Time Travel Debugging
Replay test executions from any checkpoint

### CI/CD Integration
AI-powered test impact analysis for 10x faster pipelines

### Multi-Browser Support
Chrome, Firefox, Safari, Edge via Selenium Grid

## License

MIT

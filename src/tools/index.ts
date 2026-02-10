/**
 * Tool module registry.
 *
 * Each tool module exports a `register(server, agent)` function.
 * Import and call each module here to register all tools with the MCP server.
 *
 * Architecture note: The main `src/index.ts` currently contains all tools inline.
 * New tools should be added as separate modules in this directory following
 * the pattern in tests.ts, reports.ts, etc. Over time, existing inline tools
 * can be migrated here incrementally without breaking changes.
 *
 * Usage from SkopaqMcpAgentSQLite.init():
 *   import { registerAllModularTools } from "./tools/index.js";
 *   registerAllModularTools(this.server, this as AgentContext);
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AgentContext } from "./types.js";

// Import modular tool registrars as they are created
// import { register as registerTests } from "./tests.js";
// import { register as registerReports } from "./reports.js";
// import { register as registerFlaky } from "./flaky.js";
// ... add more as tools are migrated from index.ts

/**
 * Register all modular tools with the MCP server.
 * Called from SkopaqMcpAgentSQLite.init() after inline tool registration.
 */
export function registerAllModularTools(
  server: McpServer,
  agent: AgentContext,
): void {
  // As tool groups are extracted from index.ts into modules,
  // uncomment and add their registration calls here:
  //
  // registerTests(server, agent);
  // registerReports(server, agent);
  // registerFlaky(server, agent);
  // registerIntegrations(server, agent);
  // registerFailurePatterns(server, agent);
  // registerPerformance(server, agent);
  // registerAccessibility(server, agent);
  // registerSlo(server, agent);
  // registerImpactGraph(server, agent);
  // registerChat(server, agent);
  // registerParameterized(server, agent);
  // registerInsights(server, agent);
  // registerSast(server, agent);

  console.log("[Skopaq MCP] Modular tool registration ready (tools extracted incrementally)");
}

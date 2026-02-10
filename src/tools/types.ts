/**
 * Shared types and interfaces for Skopaq MCP tool modules.
 *
 * Each tool module exports a `register(server, agent)` function
 * that registers tools with the MCP server.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

/**
 * Agent context passed to each tool module.
 * Provides access to authenticated API calls and error handling.
 */
export interface AgentContext {
  /** Make an authenticated API call to the Brain backend */
  callBrainAPIWithAuth<T>(
    endpoint: string,
    method: "GET" | "POST" | "PUT" | "DELETE",
    body?: Record<string, unknown>
  ): Promise<T>;

  /** Ensure user is authenticated, throws AUTH_REQUIRED if not */
  requireAuth(): Promise<string>;

  /** Get stored access token (may be undefined) */
  getAccessToken(): Promise<string | undefined>;

  /** Standard error handler for tools */
  handleError(error: unknown): {
    content: Array<{ type: "text"; text: string }>;
    isError: true;
  };

  /** Environment variables */
  env: {
    ARGUS_BRAIN_URL: string;
    BROWSER_POOL_URL?: string;
    BROWSER_POOL_JWT_SECRET?: string;
    [key: string]: unknown;
  };
}

/**
 * Tool module registration function signature.
 * Each module in tools/ exports a function matching this type.
 */
export type ToolRegistrar = (
  server: McpServer,
  agent: AgentContext
) => void;

// =====================================================
// Shared Response Types (used across multiple modules)
// =====================================================

export interface ProjectsResponse {
  projects: Array<{
    id: string;
    name: string;
    description?: string;
    repository_url?: string;
    app_url?: string;
    created_at: string;
    organization_id: string;
  }>;
}

export interface BrainQualityScoreResponse {
  score: number;
  components: {
    coverage: number;
    reliability: number;
    freshness: number;
    severity_coverage: number;
  };
  grade: string;
}

export interface BrainQualityStatsResponse {
  stats: {
    total_events: number;
    coverage_rate: number;
    total_generated_tests: number;
    avg_risk_score: number;
  };
}

export interface BrainRiskScoresResponse {
  risk_scores: Array<{
    event_id: string;
    title: string;
    risk_score: number;
    severity: string;
    has_test: boolean;
    factors: Record<string, number>;
  }>;
}

export interface FlakyTestsResponse {
  flaky_tests: Array<{
    test_id: string;
    test_name: string;
    flakiness_score: number;
    pass_rate: number;
    total_runs: number;
    last_flaky_at: string;
    failure_patterns: string[];
  }>;
}

export interface CoverageGapsResponse {
  gaps: Array<{
    area: string;
    risk_level: string;
    description: string;
    suggested_tests: string[];
  }>;
}

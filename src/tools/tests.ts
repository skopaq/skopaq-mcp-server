/**
 * Test CRUD tools for Skopaq MCP Server.
 *
 * Provides tools for managing tests (list, get, create, update, delete).
 * These cover the primary /api/v1/tests endpoints.
 *
 * Migration note: These tools are currently also defined inline in index.ts.
 * Once this module is activated in tools/index.ts, the corresponding inline
 * tools should be removed from index.ts to avoid duplicates.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AgentContext } from "./types.js";

export function register(server: McpServer, agent: AgentContext): void {

  // argus_test_list - List tests for a project
  server.tool(
    "argus_test_list",
    "List all tests for a project with optional filtering by status, type, or search query.",
    {
      project_id: z.string().describe("The project UUID"),
      status: z.enum(["all", "active", "disabled", "draft"]).optional().describe("Filter by test status"),
      type: z.string().optional().describe("Filter by test type (e.g., 'e2e', 'api', 'unit')"),
      search: z.string().optional().describe("Search query to filter tests by name"),
      limit: z.number().optional().describe("Max results (default 50)"),
      offset: z.number().optional().describe("Pagination offset"),
    },
    async ({ project_id, status, type, search, limit, offset }) => {
      try {
        await agent.requireAuth();
        const params = new URLSearchParams({ project_id });
        if (status && status !== "all") params.append("status", status);
        if (type) params.append("type", type);
        if (search) params.append("search", search);
        if (limit) params.append("limit", String(limit));
        if (offset) params.append("offset", String(offset));

        const result = await agent.callBrainAPIWithAuth<{
          tests: Array<{ id: string; name: string; status: string; type: string; created_at: string; last_run_at?: string }>;
          total: number;
        }>(
          `/api/v1/tests?${params.toString()}`,
          "GET"
        );

        let output = `## Tests (${result.total} total)\n\n`;
        output += `| # | Name | Status | Type | Last Run |\n|---|------|--------|------|----------|\n`;
        (result.tests || []).forEach((t, i) => {
          output += `| ${i + 1} | ${t.name} | ${t.status} | ${t.type || "-"} | ${t.last_run_at ? new Date(t.last_run_at).toLocaleDateString() : "Never"} |\n`;
        });

        return { content: [{ type: "text" as const, text: output }] };
      } catch (error) { return agent.handleError(error); }
    }
  );

  // argus_test_get - Get a single test by ID
  server.tool(
    "argus_test_get",
    "Get full details of a specific test including steps, assertions, and run history.",
    {
      test_id: z.string().describe("The test UUID"),
    },
    async ({ test_id }) => {
      try {
        await agent.requireAuth();
        const result = await agent.callBrainAPIWithAuth<{
          id: string; name: string; description?: string; steps: unknown[]; status: string;
          type: string; created_at: string; updated_at: string; tags?: string[];
        }>(
          `/api/v1/tests/${test_id}`,
          "GET"
        );

        let output = `## Test: ${result.name}\n\n`;
        output += `| Field | Value |\n|-------|-------|\n`;
        output += `| **ID** | \`${result.id}\` |\n`;
        output += `| **Status** | ${result.status} |\n`;
        output += `| **Type** | ${result.type || "-"} |\n`;
        output += `| **Created** | ${new Date(result.created_at).toLocaleString()} |\n`;
        output += `| **Updated** | ${new Date(result.updated_at).toLocaleString()} |\n`;
        if (result.tags?.length) output += `| **Tags** | ${result.tags.join(", ")} |\n`;
        if (result.description) output += `\n**Description:** ${result.description}\n`;
        if (result.steps?.length) output += `\n**Steps:** ${result.steps.length} step(s)\n`;

        return { content: [{ type: "text" as const, text: output }] };
      } catch (error) { return agent.handleError(error); }
    }
  );

  // argus_test_create - Create a new test
  server.tool(
    "argus_test_create",
    "Create a new test case with name, steps, and optional metadata.",
    {
      project_id: z.string().describe("The project UUID"),
      name: z.string().describe("Test name"),
      description: z.string().optional().describe("Test description"),
      type: z.string().optional().describe("Test type (e.g., 'e2e', 'api')"),
      steps: z.array(z.object({
        action: z.string().describe("Step action"),
        target: z.string().optional().describe("Target selector/URL"),
        value: z.string().optional().describe("Input value"),
        assertion: z.string().optional().describe("Expected assertion"),
      })).optional().describe("Test steps"),
      tags: z.array(z.string()).optional().describe("Tags for the test"),
    },
    async ({ project_id, name, description, type, steps, tags }) => {
      try {
        await agent.requireAuth();
        const result = await agent.callBrainAPIWithAuth<{ id: string; name: string; status: string }>(
          `/api/v1/tests`,
          "POST",
          { project_id, name, description, type, steps, tags }
        );

        return {
          content: [{
            type: "text" as const,
            text: `## Test Created\n\n**ID:** \`${result.id}\`\n**Name:** ${result.name}\n**Status:** ${result.status}\n\n**Next:** Use \`argus_test_run_create\` to execute this test.`,
          }],
        };
      } catch (error) { return agent.handleError(error); }
    }
  );

  // argus_test_update - Update an existing test
  server.tool(
    "argus_test_update",
    "Update a test's name, description, steps, status, or tags.",
    {
      test_id: z.string().describe("The test UUID"),
      name: z.string().optional().describe("New test name"),
      description: z.string().optional().describe("New description"),
      status: z.string().optional().describe("New status"),
      steps: z.array(z.object({
        action: z.string(),
        target: z.string().optional(),
        value: z.string().optional(),
        assertion: z.string().optional(),
      })).optional().describe("Updated steps"),
      tags: z.array(z.string()).optional().describe("Updated tags"),
    },
    async ({ test_id, ...updates }) => {
      try {
        await agent.requireAuth();
        const result = await agent.callBrainAPIWithAuth<{
          id: string; name: string; status: string; updated_at: string;
        }>(
          `/api/v1/tests/${test_id}`,
          "PUT",
          updates
        );

        return {
          content: [{
            type: "text" as const,
            text: `## Test Updated\n\n**ID:** \`${result.id}\`\n**Name:** ${result.name}\n**Status:** ${result.status}\n**Updated:** ${new Date(result.updated_at).toLocaleString()}`,
          }],
        };
      } catch (error) { return agent.handleError(error); }
    }
  );

  // argus_test_delete - Delete a test
  server.tool(
    "argus_test_delete",
    "Permanently delete a test case. This cannot be undone.",
    {
      test_id: z.string().describe("The test UUID to delete"),
    },
    async ({ test_id }) => {
      try {
        await agent.requireAuth();
        await agent.callBrainAPIWithAuth<{ success: boolean }>(
          `/api/v1/tests/${test_id}`,
          "DELETE"
        );

        return {
          content: [{
            type: "text" as const,
            text: `## Test Deleted\n\nTest \`${test_id}\` has been permanently deleted.`,
          }],
        };
      } catch (error) { return agent.handleError(error); }
    }
  );
}

/**
 * Skopaq MCP Server - Standalone Node.js Version
 *
 * This server provides MCP (Model Context Protocol) capabilities for
 * self-hosted and air-gap deployments. It proxies tool requests to
 * the Skopaq Brain API while handling screenshots locally via MinIO.
 *
 * RAP-295: Air-Gap Foundation - MCP Server Docker Image
 */

import express, { Request, Response, NextFunction } from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types";
import { v4 as uuidv4 } from "uuid";
import { loadConfig, type Config } from "./config";
import { createStorageAdapter, type StorageAdapter } from "./storage";
import {
  SessionManager,
  InMemorySessionManager,
  type Session,
} from "./session";

// Load configuration
const config = loadConfig();

// Initialize storage and session managers
const storage = createStorageAdapter(config);
const sessions =
  config.REDIS_URL && config.REDIS_URL !== "redis://localhost:6379"
    ? new SessionManager(config)
    : new InMemorySessionManager();

// MCP Tool definitions (subset - full list in tool registry)
const TOOLS = [
  {
    name: "argus_health",
    description: "Check Skopaq API health status",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "argus_discover",
    description:
      "Discover interactive elements on a web page. Returns all clickable, typeable, and interactive elements with their selectors.",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "URL of the page to analyze",
        },
        wait_for: {
          type: "string",
          description: "Optional CSS selector to wait for before analysis",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "argus_act",
    description:
      "Execute browser actions (click, type, navigate, scroll, etc.)",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "URL of the page to act on",
        },
        actions: {
          type: "array",
          items: {
            type: "object",
            properties: {
              type: {
                type: "string",
                enum: [
                  "click",
                  "type",
                  "navigate",
                  "scroll",
                  "wait",
                  "screenshot",
                ],
              },
              selector: { type: "string" },
              value: { type: "string" },
            },
          },
          description: "Array of actions to execute",
        },
      },
      required: ["url", "actions"],
    },
  },
  {
    name: "argus_test",
    description:
      "Run a multi-step E2E test with screenshots captured at each step",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "Starting URL for the test",
        },
        steps: {
          type: "array",
          items: {
            type: "object",
            properties: {
              action: { type: "string" },
              target: { type: "string" },
              value: { type: "string" },
              assertion: { type: "string" },
            },
          },
          description: "Test steps to execute",
        },
        name: {
          type: "string",
          description: "Optional test name",
        },
      },
      required: ["url", "steps"],
    },
  },
  {
    name: "argus_agent",
    description:
      "Autonomous task completion - give a goal and the agent will figure out how to achieve it",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "Starting URL",
        },
        task: {
          type: "string",
          description:
            "Natural language description of what to accomplish",
        },
        max_steps: {
          type: "number",
          description: "Maximum steps to attempt (default: 10)",
        },
      },
      required: ["url", "task"],
    },
  },
  {
    name: "argus_extract",
    description: "Extract structured data from a web page",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "URL of the page to extract from",
        },
        schema: {
          type: "object",
          description: "Schema describing the data to extract",
        },
      },
      required: ["url", "schema"],
    },
  },
  {
    name: "argus_generate_test",
    description: "Generate test steps from a natural language description",
    inputSchema: {
      type: "object" as const,
      properties: {
        description: {
          type: "string",
          description: "Natural language description of the test",
        },
        url: {
          type: "string",
          description: "Optional starting URL",
        },
      },
      required: ["description"],
    },
  },
];

/**
 * Create MCP server with all tools
 */
function createMcpServer(): Server {
  const server = new Server(
    {
      name: "argus-mcp-server",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // List available tools
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: TOOLS };
  });

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      // Proxy to Brain API
      const response = await fetch(
        `${config.ARGUS_BRAIN_URL}/api/v1/mcp/tools/${name}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(config.API_TOKEN
              ? { "X-API-Key": config.API_TOKEN }
              : {}),
          },
          body: JSON.stringify(args),
        }
      );

      if (!response.ok) {
        const error = await response.text();
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${response.status} - ${error}`,
            },
          ],
          isError: true,
        };
      }

      const result = await response.json();

      // Handle screenshots if present
      if (result.screenshots && Array.isArray(result.screenshots)) {
        const sessionId = uuidv4();
        const screenshotUrls: string[] = [];

        for (let i = 0; i < result.screenshots.length; i++) {
          const upload = await storage.storeScreenshot(
            result.screenshots[i],
            sessionId,
            i
          );
          if (upload.success && upload.url) {
            screenshotUrls.push(upload.url);
          }
        }

        result.screenshot_urls = screenshotUrls;
        delete result.screenshots; // Don't send raw base64 back
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error calling tool ${name}: ${error instanceof Error ? error.message : "Unknown error"}`,
          },
        ],
        isError: true,
      };
    }
  });

  return server;
}

/**
 * Start Express server with MCP SSE endpoint
 */
async function startServer(): Promise<void> {
  const app = express();

  // Middleware
  app.use(express.json({ limit: "50mb" }));

  // CORS
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.header("Access-Control-Allow-Origin", config.CORS_ORIGINS);
    res.header(
      "Access-Control-Allow-Headers",
      "Origin, X-Requested-With, Content-Type, Accept, Authorization"
    );
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") {
      return res.sendStatus(200);
    }
    next();
  });

  // Health check
  app.get("/health", async (_req: Request, res: Response) => {
    const storageHealth = await storage.healthCheck();
    const sessionHealth = await sessions.healthCheck();

    const healthy = storageHealth.healthy && sessionHealth.healthy;

    res.status(healthy ? 200 : 503).json({
      status: healthy ? "healthy" : "unhealthy",
      storage: storageHealth,
      sessions: sessionHealth,
      timestamp: new Date().toISOString(),
    });
  });

  // Root endpoint - server info
  app.get("/", (_req: Request, res: Response) => {
    res.json({
      name: "Skopaq MCP Server (Standalone)",
      version: "1.0.0",
      description:
        "Model Context Protocol server for Skopaq E2E Testing - Self-hosted version",
      endpoints: {
        sse: "/sse",
        health: "/health",
        screenshots: "/screenshot/:key",
      },
      tools: TOOLS.map((t) => t.name),
      documentation: "https://docs.skopaq.ai/self-hosted",
    });
  });

  // SSE endpoint for MCP
  const mcpConnections = new Map<string, Server>();

  app.get("/sse", async (req: Request, res: Response) => {
    // Set up SSE headers
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    const connectionId = uuidv4();
    const server = createMcpServer();

    mcpConnections.set(connectionId, server);

    // Create SSE transport
    const transport = new SSEServerTransport("/sse/message", res);

    // Clean up on disconnect
    req.on("close", () => {
      mcpConnections.delete(connectionId);
      transport.close();
    });

    // Connect server to transport
    await server.connect(transport);

    console.log(`MCP connection established: ${connectionId}`);
  });

  // SSE message endpoint
  app.post("/sse/message", async (req: Request, res: Response) => {
    // Handle incoming messages - the SSE transport manages this
    res.status(200).json({ received: true });
  });

  // Screenshot serving endpoint
  app.get("/screenshot/:key(*)", async (req: Request, res: Response) => {
    const key = req.params.key;
    const token = req.query.t as string;

    // TODO: Validate token if JWT_SECRET is configured

    const data = await storage.getScreenshot(key);
    if (!data) {
      return res.status(404).send("Screenshot not found");
    }

    res.setHeader("Content-Type", "image/png");
    res.setHeader("Cache-Control", "private, max-age=3600");
    res.send(data);
  });

  // Connect to services
  await sessions.connect();
  console.log("Connected to session store");

  // Ensure storage bucket exists (for MinIO)
  if ("ensureBucket" in storage) {
    await (storage as { ensureBucket: () => Promise<void> }).ensureBucket();
    console.log("Storage bucket ready");
  }

  // Start server
  app.listen(config.PORT, config.HOST, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   Skopaq MCP Server (Standalone)                          ║
║   Self-hosted / Air-Gap Deployment                       ║
║                                                           ║
║   Server running at: http://${config.HOST}:${config.PORT}          ║
║   SSE Endpoint: http://${config.HOST}:${config.PORT}/sse            ║
║   Health Check: http://${config.HOST}:${config.PORT}/health         ║
║                                                           ║
║   Brain API: ${config.ARGUS_BRAIN_URL}
║   Storage: ${config.STORAGE_PROVIDER}                               ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    `);
  });

  // Graceful shutdown
  process.on("SIGTERM", async () => {
    console.log("Shutting down...");
    await sessions.close();
    process.exit(0);
  });
}

// Start the server
startServer().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});

/**
 * Skopaq MCP Server - Model Context Protocol for AI IDEs
 * https://skopaq.ai
 *
 * This MCP server exposes Skopaq E2E testing capabilities to AI coding assistants:
 * - Claude Code
 * - Cursor
 * - Windsurf
 * - VS Code with MCP extension
 *
 * Tools provided:
 * - argus_discover: Discover interactive elements on a page
 * - argus_test: Run multi-step E2E tests with screenshots
 * - argus_act: Execute browser actions
 * - argus_extract: Extract data from pages
 * - argus_agent: Autonomous task completion
 * - argus_health: Check Skopaq API status
 */

import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as Sentry from "@sentry/cloudflare";

// Environment types
interface Env {
  AI: Ai;
  SCREENSHOTS: R2Bucket;  // R2 storage for screenshots
  SCREENSHOTS_PUBLIC_URL?: string;  // Public URL for R2 screenshots
  BROWSER_POOL_URL?: string;  // Primary - Vultr VKE browser pool
  BROWSER_POOL_JWT_SECRET?: string;  // JWT secret for pool auth (production)
  BROWSER_POOL_API_KEY?: string;  // Legacy API key (deprecated)
  ARGUS_API_URL: string;  // Fallback - Cloudflare browser automation
  ARGUS_BRAIN_URL: string;  // Brain - intelligence
  API_TOKEN?: string;
  ANTHROPIC_API_KEY?: string;
  MCP_OAUTH: DurableObjectNamespace;
  MCP_OBJECT: DurableObjectNamespace;
  // Sentry configuration
  SENTRY_DSN?: string;
}

// =====================================================
// JWT Token Signing for Browser Pool (Production-Grade)
// =====================================================

interface PoolTokenPayload {
  iss: string;      // Issuer: 'argus-mcp'
  sub: string;      // User ID
  aud: string;      // Audience: 'browser-pool'
  exp: number;      // Expiration
  iat: number;      // Issued at
  jti: string;      // Unique token ID
  org_id?: string;  // Organization ID
  email?: string;   // User email (for audit)
  action?: string;  // Action being performed
  ip?: string;      // Client IP
}

function base64UrlEncode(data: string | ArrayBuffer): string {
  const bytes = typeof data === 'string'
    ? new TextEncoder().encode(data)
    : new Uint8Array(data);
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function signPoolToken(
  payload: Omit<PoolTokenPayload, 'iat' | 'exp' | 'jti'>,
  secret: string,
  expiresInSeconds: number = 300
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const fullPayload: PoolTokenPayload = {
    ...payload,
    iat: now,
    exp: now + expiresInSeconds,
    jti: crypto.randomUUID(),
  };

  const header = { alg: 'HS256', typ: 'JWT' };
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(fullPayload));

  // Sign using Web Crypto API (Cloudflare Workers compatible)
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(`${headerB64}.${payloadB64}`)
  );

  const signatureB64 = base64UrlEncode(signature);
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

// =====================================================
// R2 Screenshot Storage
// =====================================================

// MCP server base URL for screenshot serving
const MCP_SERVER_URL = "https://argus-mcp.samuelvinay-kumar.workers.dev";

// Screenshot URL expiry time (1 hour)
const SCREENSHOT_URL_EXPIRY_MS = 60 * 60 * 1000;

interface ScreenshotUploadResult {
  success: boolean;
  url?: string;
  key?: string;
  error?: string;
}

/**
 * Generate a signed token for screenshot access
 * Token format: base64url(expiry:signature)
 * This combines expiry into the token to avoid URL truncation issues with &
 */
async function generateScreenshotToken(key: string, expiry: number, env: Env): Promise<string> {
  const secret = env.BROWSER_POOL_JWT_SECRET;
  if (!secret) {
    throw new Error("BROWSER_POOL_JWT_SECRET is required for screenshot signing - refusing to use insecure default");
  }
  const data = `${key}:${expiry}`;

  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    encoder.encode(data)
  );

  const sigB64 = base64UrlEncode(signature);
  // Combine expiry and signature into single token: expiry.signature
  return `${expiry}.${sigB64}`;
}

/**
 * Parse and validate a screenshot token
 * Returns { valid: true, expiry } or { valid: false, error }
 */
async function validateScreenshotToken(
  token: string,
  key: string,
  env: Env
): Promise<{ valid: boolean; expiry?: number; error?: string }> {
  const parts = token.split(".");
  if (parts.length !== 2) {
    return { valid: false, error: "Invalid token format" };
  }

  const [expiryStr, signature] = parts;
  const expiry = parseInt(expiryStr, 10);

  if (isNaN(expiry)) {
    return { valid: false, error: "Invalid expiry in token" };
  }

  if (Date.now() > expiry) {
    return { valid: false, error: "Token expired" };
  }

  // Regenerate expected signature
  const secret = env.BROWSER_POOL_JWT_SECRET;
  if (!secret) {
    return { valid: false, error: "BROWSER_POOL_JWT_SECRET not configured" };
  }
  const data = `${key}:${expiry}`;

  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const expectedSig = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    encoder.encode(data)
  );

  const expectedSigB64 = base64UrlEncode(expectedSig);

  if (signature !== expectedSigB64) {
    return { valid: false, error: "Invalid signature" };
  }

  return { valid: true, expiry };
}

/**
 * Generate a signed URL for accessing a screenshot
 * URL expires after SCREENSHOT_URL_EXPIRY_MS
 * Uses single token parameter to avoid & truncation issues
 */
async function generateSignedScreenshotUrl(key: string, env: Env): Promise<string> {
  const expiry = Date.now() + SCREENSHOT_URL_EXPIRY_MS;
  const token = await generateScreenshotToken(key, expiry, env);

  // Single parameter URL to avoid & truncation in markdown/terminals
  return `${MCP_SERVER_URL}/screenshot/${encodeURIComponent(key)}?t=${token}`;
}

/**
 * Store a screenshot in R2 and return a signed URL
 */
async function storeScreenshot(
  env: Env,
  screenshotData: unknown,  // Can be string, Buffer object, or serialized Buffer
  sessionId: string,
  identifier: string | number,  // step index or 'final'
  metadata?: Record<string, string>
): Promise<ScreenshotUploadResult> {
  if (!env.SCREENSHOTS) {
    console.warn("[R2] Screenshots bucket not configured");
    return { success: false, error: "R2 storage not configured" };
  }

  try {
    // Generate key: mcp-screenshots/{session_id}/{identifier}.png
    const key = `mcp-screenshots/${sessionId}/${identifier}.png`;

    // Handle different input formats
    let bytes: Uint8Array;

    if (!screenshotData) {
      console.error(`[R2] Screenshot data is null/undefined`);
      return { success: false, error: "Screenshot data is null/undefined" };
    }

    // Case 1: Already a base64 string
    if (typeof screenshotData === "string") {
      console.log(`[R2] Processing base64 string: length=${screenshotData.length}`);

      // Clean and convert base64 to ArrayBuffer
      let cleanBase64 = screenshotData
        .replace(/^data:image\/\w+;base64,/, "")  // Remove data URL prefix if present
        .replace(/[\s\n\r]/g, "")                  // Remove whitespace
        .replace(/-/g, "+")                        // URL-safe base64 to standard
        .replace(/_/g, "/");

      // Add padding if needed
      const paddingNeeded = (4 - (cleanBase64.length % 4)) % 4;
      cleanBase64 += "=".repeat(paddingNeeded);

      const binaryString = atob(cleanBase64);
      bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
    }
    // Case 2: Serialized Node.js Buffer ({ type: 'Buffer', data: [...] })
    else if (
      typeof screenshotData === "object" &&
      screenshotData !== null &&
      "type" in screenshotData &&
      (screenshotData as { type: string }).type === "Buffer" &&
      "data" in screenshotData &&
      Array.isArray((screenshotData as { data: number[] }).data)
    ) {
      const bufferData = (screenshotData as { type: string; data: number[] }).data;
      console.log(`[R2] Processing serialized Buffer: ${bufferData.length} bytes`);
      bytes = new Uint8Array(bufferData);
    }
    // Case 3: ArrayBuffer or Uint8Array
    else if (screenshotData instanceof ArrayBuffer) {
      console.log(`[R2] Processing ArrayBuffer: ${screenshotData.byteLength} bytes`);
      bytes = new Uint8Array(screenshotData);
    }
    else if (screenshotData instanceof Uint8Array) {
      console.log(`[R2] Processing Uint8Array: ${screenshotData.length} bytes`);
      bytes = screenshotData;
    }
    // Unknown format - log details for debugging
    else {
      const objType = typeof screenshotData;
      const objKeys = typeof screenshotData === "object" && screenshotData !== null
        ? Object.keys(screenshotData).slice(0, 5).join(", ")
        : "N/A";
      const objSample = typeof screenshotData === "object" && screenshotData !== null
        ? JSON.stringify(screenshotData).slice(0, 200)
        : String(screenshotData).slice(0, 100);
      console.error(`[R2] Unknown screenshot format: type=${objType}, keys=[${objKeys}], sample=${objSample}`);
      return { success: false, error: `Unknown screenshot format: ${objType}` };
    }

    console.log(`[R2] Uploading ${bytes.length} bytes to ${key}`);

    // Upload to R2 (cast to ArrayBuffer to satisfy TypeScript)
    await env.SCREENSHOTS.put(key, bytes.buffer as ArrayBuffer, {
      httpMetadata: {
        contentType: "image/png",
        cacheControl: "private, max-age=3600",  // 1 hour cache (matches URL expiry)
      },
      customMetadata: {
        sessionId,
        identifier: String(identifier),
        uploadedAt: new Date().toISOString(),
        ...metadata,
      },
    });

    // Generate signed URL (expires in 1 hour)
    const url = await generateSignedScreenshotUrl(key, env);
    console.log(`[R2] Screenshot stored: ${key}`);

    return { success: true, url, key };
  } catch (error) {
    console.error("[R2] Screenshot upload failed:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Upload failed",
    };
  }
}

/**
 * Store multiple screenshots and return URLs
 */
async function storeScreenshots(
  env: Env,
  screenshots: string[],
  sessionId: string,
  startIndex: number = 0
): Promise<string[]> {
  const urls: string[] = [];

  for (let i = 0; i < screenshots.length; i++) {
    const result = await storeScreenshot(
      env,
      screenshots[i],
      sessionId,
      startIndex + i
    );
    if (result.success && result.url) {
      urls.push(result.url);
    }
  }

  return urls;
}

/**
 * Generate a unique session ID for screenshot grouping
 */
function generateSessionId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `${timestamp}-${random}`;
}

// User context from MCP session
interface UserContext {
  userId: string;
  orgId?: string;
  email?: string;
  ip?: string;
}

// Brain API Response types
interface BrainHealthResponse {
  status: string;
  version: string;
  timestamp: string;
}

interface BrainTestCreateResponse {
  success: boolean;
  test: {
    id: string;
    name: string;
    description: string;
    steps: Array<{
      action: string;
      target?: string;
      value?: string;
    }>;
    assertions: Array<{
      type: string;
      target?: string;
      expected?: string;
    }>;
  };
  spec?: string;
}

interface BrainQualityStatsResponse {
  stats: {
    total_events: number;
    events_by_status: Record<string, number>;
    events_by_severity: Record<string, number>;
    total_generated_tests: number;
    tests_by_status: Record<string, number>;
    coverage_rate: number;
  };
}

interface BrainQualityScoreResponse {
  quality_score: number;
  risk_level: string;
  test_coverage: number;
  total_events: number;
  total_tests: number;
  approved_tests: number;
}

interface BrainRiskScoresResponse {
  success: boolean;
  risk_scores: Array<{
    entity_type: string;
    entity_identifier: string;
    overall_score: number;
    factors: Record<string, number>;
    error_count: number;
    affected_users: number;
    trend: string;
  }>;
  total_entities: number;
}

// Sync API Response types
interface SyncPushResponse {
  success: boolean;
  events_pushed: number;
  new_version?: number;
  conflicts?: Array<{
    id: string;
    test_id: string;
    path: string[];
    local_value: unknown;
    remote_value: unknown;
  }>;
  error?: string;
}

interface SyncPullResponse {
  success: boolean;
  events: Array<{
    id: string;
    type: string;
    test_id: string;
    content?: Record<string, unknown>;
    timestamp: string;
  }>;
  new_version?: number;
  error?: string;
}

interface SyncStatusResponse {
  success: boolean;
  project_id: string;
  status: string;
  tests: Record<string, {
    test_id: string;
    status: string;
    local_version: number;
    remote_version: number;
    pending_changes: number;
    conflicts: number;
  }>;
  total_pending: number;
  total_conflicts: number;
}

interface SyncResolveResponse {
  success: boolean;
  resolved: boolean;
  conflict_id: string;
  resolved_value?: unknown;
  error?: string;
}

// Export API Response types
interface ExportResponse {
  success: boolean;
  language: string;
  framework: string;
  code: string;
  filename: string;
  imports?: string[];
  error?: string;
}

interface ExportLanguagesResponse {
  languages: Array<{
    id: string;
    name: string;
    frameworks: string[];
  }>;
}

// Recording API Response types
interface RecordingConvertResponse {
  success: boolean;
  test: {
    id: string;
    name: string;
    source: string;
    steps: Array<{
      action: string;
      target?: string;
      value?: string;
    }>;
    assertions: Array<{
      type: string;
      target?: string;
      expected?: string;
    }>;
  };
  recording_id: string;
  duration_ms: number;
  events_processed: number;
  error?: string;
}

// Collaboration API Response types
interface PresenceResponse {
  success: boolean;
  users: Array<{
    user_id: string;
    user_name: string;
    status: string;
    test_id?: string;
    cursor?: {
      step_index?: number;
      field?: string;
    };
    color: string;
    last_active: string;
  }>;
}

// Production Events Response types
interface ProductionEventsResponse {
  events: Array<{
    id: string;
    title: string;
    message?: string;
    severity: string;
    status: string;
    url?: string;
    component?: string;
    occurrence_count: number;
    affected_users: number;
    source: string;
    first_seen_at: string;
    last_seen_at: string;
    ai_analysis?: {
      generated_test_id?: string;
      confidence_score?: number;
    };
  }>;
}

// Generated Tests Response types
interface GeneratedTestsResponse {
  tests: Array<{
    id: string;
    name: string;
    description?: string;
    status: string;
    framework: string;
    test_code?: string;
    test_file_path?: string;
    confidence_score: number;
    production_event_id?: string;
    created_at: string;
    reviewed_at?: string;
  }>;
}

// Healing Config Response types
interface HealingConfigResponse {
  id: string;
  organization_id: string;
  project_id?: string;
  enabled: boolean;
  auto_apply: boolean;
  min_confidence_auto: number;
  min_confidence_suggest: number;
  heal_selectors: boolean;
  heal_timeouts: boolean;
  heal_text_content: boolean;
  learn_from_success: boolean;
  notify_on_heal: boolean;
  require_approval: boolean;
}

// Healing Patterns Response types
interface HealingPatternsResponse {
  patterns: Array<{
    id: string;
    fingerprint: string;
    original_selector: string;
    healed_selector: string;
    error_type: string;
    success_count: number;
    failure_count: number;
    confidence: number;
    project_id?: string;
    created_at: string;
  }>;
}

// Healing Stats Response types
interface HealingStatsResponse {
  total_patterns: number;
  total_heals_applied: number;
  total_heals_suggested: number;
  success_rate: number;
  top_error_types: Record<string, number>;
  heals_last_24h: number;
  heals_last_7d: number;
  avg_confidence: number;
  recent_heals: Array<{
    id: string;
    original: string;
    healed: string;
    error_type: string;
    confidence: number;
  }>;
}

// Projects Response types
interface ProjectsResponse {
  projects: Array<{
    id: string;
    name: string;
    description?: string;
    app_url?: string;
    organization_id: string;
    created_at: string;
    test_count?: number;
    event_count?: number;
  }>;
}

// Test Run History Response types
interface TestRunHistoryResponse {
  runs: Array<{
    id: string;
    test_id: string;
    status: string;
    duration_ms: number;
    passed_steps: number;
    total_steps: number;
    error_message?: string;
    screenshot_url?: string;
    started_at: string;
    completed_at?: string;
  }>;
}

// What To Test Response types
interface WhatToTestResponse {
  recommendations: Array<{
    priority: string;
    entity: string;
    entity_type: string;
    reason: string;
    risk_score: number;
    affected_users: number;
    suggested_test_description: string;
  }>;
  summary: string;
}

// Coverage Gaps Response types
interface CoverageGapsResponse {
  gaps: Array<{
    entity: string;
    entity_type: string;
    error_count: number;
    has_test: boolean;
    risk_score: number;
    suggestion: string;
  }>;
  coverage_percentage: number;
  total_entities: number;
  tested_entities: number;
}

// Flaky Tests Response types
interface FlakyTestsResponse {
  flaky_tests: Array<{
    test_id: string;
    test_name: string;
    flakiness_score: number;
    pass_rate: number;
    total_runs: number;
    recent_failures: number;
    common_failure_reason?: string;
  }>;
  total_flaky: number;
}

// Schedule Response types
interface ScheduleResponse {
  schedules: Array<{
    id: string;
    name: string;
    cron_expression: string;
    test_ids: string[];
    enabled: boolean;
    last_run_at?: string;
    next_run_at?: string;
    created_at: string;
  }>;
}

interface ScheduleCreateResponse {
  success: boolean;
  schedule: {
    id: string;
    name: string;
    cron_expression: string;
    test_ids: string[];
    enabled: boolean;
    next_run_at?: string;
    created_at: string;
  };
  error?: string;
}

interface ScheduleRunResponse {
  success: boolean;
  run_id: string;
  schedule_id: string;
  status: string;
  started_at: string;
  message?: string;
  error?: string;
}

interface ScheduleHistoryResponse {
  success: boolean;
  schedule_id: string;
  runs: Array<{
    id: string;
    status: string;
    started_at: string;
    completed_at?: string;
    duration_ms?: number;
    tests_run: number;
    tests_passed: number;
    tests_failed: number;
    error?: string;
  }>;
  total: number;
}

// AI Ask Response types
interface AskResponse {
  answer: string;
  sources: Array<{
    type: string;
    id: string;
    relevance: number;
  }>;
  suggestions?: string[];
}

interface CommentsResponse {
  success: boolean;
  comments: Array<{
    id: string;
    test_id: string;
    step_index?: number;
    author_id: string;
    author_name: string;
    content: string;
    mentions: string[];
    resolved: boolean;
    created_at: string;
    replies?: Array<{
      id: string;
      author_id: string;
      author_name: string;
      content: string;
      created_at: string;
    }>;
  }>;
}

// Infrastructure & Cost Response types
interface InfraCostOverviewResponse {
  currentMonthCost: number;
  projectedMonthCost: number;
  browserStackEquivalent: number;
  savingsPercentage: number;
  totalNodes: number;
  totalPods: number;
}

interface InfraRecommendation {
  id: string;
  type: "scale_down" | "scale_up" | "optimize" | "alert";
  title: string;
  description: string;
  potential_savings: number;
  confidence: number;
  status: "pending" | "applied" | "dismissed";
  auto_applicable: boolean;
  action?: Record<string, unknown>;
}

interface InfraRecommendationsResponse {
  recommendations: InfraRecommendation[];
  total_potential_savings: number;
}

interface InfraSnapshotResponse {
  selenium: {
    status: string;
    ready_nodes: number;
    queue_length: number;
    active_sessions: number;
    max_sessions: number;
  };
  chrome_nodes: {
    ready: number;
    busy: number;
    total: number;
    utilization: number;
  };
  firefox_nodes: {
    ready: number;
    busy: number;
    total: number;
    utilization: number;
  };
  edge_nodes: {
    ready: number;
    busy: number;
    total: number;
    utilization: number;
  };
  total_pods: number;
  total_nodes: number;
  cluster_cpu_utilization: number;
  cluster_memory_utilization: number;
  timestamp: string;
}

interface LLMUsageResponse {
  models: Array<{
    name: string;
    provider: string;
    input_tokens: number;
    output_tokens: number;
    cost: number;
    requests: number;
  }>;
  features: Array<{
    name: string;
    cost: number;
    percentage: number;
    requests: number;
  }>;
  total_cost: number;
  total_requests: number;
  total_input_tokens: number;
  total_output_tokens: number;
  period: string;
}

interface InfraSavingsResponse {
  total_monthly_savings: number;
  recommendations_applied: number;
  current_monthly_cost: number;
  browserstack_equivalent: number;
  savings_vs_browserstack: number;
  savings_percentage: number;
}

// Discovery API Response types
interface DiscoveryStartResponse {
  success: boolean;
  session_id: string;
  status: string;
  pages_discovered?: number;
  flows_found?: number;
  estimated_completion?: string;
  error?: string;
}

interface DiscoveryFlow {
  id: string;
  name: string;
  description: string;
  steps: Array<{
    action: string;
    target?: string;
    value?: string;
    screenshot_url?: string;
  }>;
  entry_point: string;
  exit_point?: string;
  confidence: number;
  discovered_at: string;
  user_journey_type?: string;
}

interface DiscoveryFlowsResponse {
  success: boolean;
  flows: DiscoveryFlow[];
  total_flows: number;
  session_id?: string;
  error?: string;
}

interface DiscoveryGenerateResponse {
  success: boolean;
  test: {
    id: string;
    name: string;
    description: string;
    steps: Array<{
      action: string;
      target?: string;
      value?: string;
    }>;
    assertions: Array<{
      type: string;
      target?: string;
      expected?: string;
    }>;
  };
  flow_id: string;
  confidence: number;
  error?: string;
}

interface DiscoveryCompareResponse {
  success: boolean;
  comparison: {
    session_1: {
      session_id: string;
      pages_count: number;
      flows_count: number;
      timestamp: string;
    };
    session_2: {
      session_id: string;
      pages_count: number;
      flows_count: number;
      timestamp: string;
    };
    new_flows: string[];
    removed_flows: string[];
    changed_flows: Array<{
      flow_id: string;
      changes: string[];
    }>;
    summary: string;
  };
  error?: string;
}

// CI/CD Response types (RAP-276)
interface CICDChangedFile {
  path: string;
  change_type: string;
  additions: number;
  deletions: number;
  impact_score?: number;
}

interface CICDImpactedTest {
  test_id: string;
  test_name: string;
  impact_score: number;
  reason: string;
  priority: string;
}

interface CICDTestImpactResponse {
  id: string;
  project_id: string;
  commit_sha: string;
  branch: string;
  base_sha?: string;
  changed_files: CICDChangedFile[];
  impacted_tests: CICDImpactedTest[];
  total_files_changed: number;
  total_tests_impacted: number;
  recommended_tests: string[];
  skip_candidates: string[];
  confidence_score: number;
  analysis_time_ms: number;
  created_at: string;
}

interface CICDRiskFactor {
  category: string;
  severity: string;
  description: string;
  score: number;
}

interface CICDDeploymentRiskResponse {
  project_id: string;
  commit_sha?: string;
  risk_score: number;
  risk_level: string;
  factors: Record<string, number | string | null>;
  recommendations: string[];
  tests_to_run: number;
  skip_candidates: number;
  created_at: string;
}

interface CICDBuild {
  id: string;
  project_id: string;
  pipeline_id?: string;
  provider: string;
  build_number: number;
  name: string;
  branch: string;
  status: string;
  commit_sha: string;
  commit_message?: string;
  commit_author?: string;
  tests_total: number;
  tests_passed: number;
  tests_failed: number;
  tests_skipped: number;
  coverage_percent?: number;
  artifact_urls: string[];
  logs_url?: string;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  metadata: Record<string, unknown>;
  created_at: string;
}

interface CICDBuildsResponse {
  builds: CICDBuild[];
  total: number;
}

interface CICDPipelineStage {
  id: string;
  name: string;
  status: string;
  started_at?: string;
  completed_at?: string;
  duration_seconds?: number;
  jobs: Array<Record<string, unknown>>;
}

interface CICDPipeline {
  id: string;
  project_id: string;
  workflow_id?: string;
  workflow_name?: string;
  run_number?: number;
  branch?: string;
  commit_sha?: string;
  commit_message?: string;
  status: string;
  conclusion?: string;
  event?: string;
  actor?: string;
  html_url?: string;
  created_at: string;
  updated_at?: string;
  started_at?: string;
  completed_at?: string;
  stages: CICDPipelineStage[];
}

interface CICDPipelinesResponse {
  pipelines: CICDPipeline[];
  total: number;
}

// Time Travel Debugging Response types
interface TimeTravelCheckpoint {
  checkpoint_id: string;
  thread_id: string;
  node_name: string;
  created_at: string;
  state_summary: {
    test_count?: number;
    failures_count?: number;
    current_step?: string;
  };
  metadata?: Record<string, unknown>;
}

interface TimeTravelCheckpointsResponse {
  checkpoints: TimeTravelCheckpoint[];
  total: number;
  project_id: string;
}

interface TimeTravelHistoryEntry {
  checkpoint_id: string;
  node_name: string;
  transition_from?: string;
  created_at: string;
  state?: Record<string, unknown>;
  changes?: {
    field: string;
    old_value: unknown;
    new_value: unknown;
  }[];
}

interface TimeTravelHistoryResponse {
  thread_id: string;
  history: TimeTravelHistoryEntry[];
  total_entries: number;
}

interface TimeTravelReplayResponse {
  success: boolean;
  new_thread_id: string;
  checkpoint_id: string;
  status: string;
  message?: string;
}

interface TimeTravelForkResponse {
  success: boolean;
  forked_thread_id: string;
  branch_name: string;
  checkpoint_id: string;
  message?: string;
}

interface TimeTravelCompareResponse {
  thread_id_1: string;
  thread_id_2: string;
  divergence_point?: {
    checkpoint_id: string;
    node_name: string;
    timestamp: string;
  };
  differences: Array<{
    field: string;
    thread_1_value: unknown;
    thread_2_value: unknown;
    first_diverged_at: string;
  }>;
  summary: {
    total_differences: number;
    thread_1_steps: number;
    thread_2_steps: number;
  };
}

// Visual AI Testing Response types (RAP-279)
interface VisualCaptureResponse {
  success: boolean;
  screenshot_id: string;
  url: string;
  screenshot_url: string;
  viewport: {
    width: number;
    height: number;
  };
  captured_at: string;
  metadata?: {
    title?: string;
    load_time_ms?: number;
    dom_elements?: number;
  };
  error?: string;
}

interface VisualCompareResponse {
  success: boolean;
  comparison_id: string;
  baseline_id: string;
  screenshot_id: string;
  match_percentage: number;
  is_match: boolean;
  diff_image_url?: string;
  differences: Array<{
    region: {
      x: number;
      y: number;
      width: number;
      height: number;
    };
    type: string;
    severity: string;
    description: string;
  }>;
  ai_analysis?: {
    summary: string;
    visual_changes: string[];
    impact_assessment: string;
    recommendation: string;
  };
  comparison_time_ms: number;
  error?: string;
}

interface VisualBaselineResponse {
  success: boolean;
  baseline_id: string;
  name: string;
  description?: string;
  screenshot_id: string;
  screenshot_url: string;
  project_id: string;
  created_at: string;
  updated_at?: string;
  error?: string;
}

interface VisualBaselinesResponse {
  baselines: Array<{
    id: string;
    name: string;
    description?: string;
    screenshot_url: string;
    url: string;
    viewport: {
      width: number;
      height: number;
    };
    created_at: string;
    updated_at?: string;
    comparison_count: number;
  }>;
  total: number;
  project_id: string;
}

interface VisualAnalyzeResponse {
  success: boolean;
  screenshot_id: string;
  analysis: {
    visual_elements: Array<{
      type: string;
      description: string;
      bounding_box: {
        x: number;
        y: number;
        width: number;
        height: number;
      };
      confidence: number;
    }>;
    layout_assessment: {
      structure: string;
      responsiveness: string;
      visual_hierarchy: string;
    };
    color_analysis?: {
      dominant_colors: string[];
      contrast_ratio?: number;
      color_scheme: string;
    };
  };
  wcag_compliance?: {
    level: string;
    score: number;
    issues: Array<{
      rule: string;
      severity: string;
      description: string;
      element?: string;
      recommendation: string;
    }>;
    passed_criteria: number;
    failed_criteria: number;
    warnings: number;
  };
  recommendations: string[];
  analysis_time_ms: number;
  error?: string;
}

// Skopaq API Response types
interface SkopaqActResponse {
  success: boolean;
  message?: string;
  actions?: Array<{
    action: string;
    selector?: string;
    value?: string;
    success: boolean;
  }>;
  screenshot?: string;
  error?: string;
}

interface SkopaqTestResponse {
  success: boolean;
  steps?: Array<{
    instruction: string;
    success: boolean;
    error?: string;
    screenshot?: string;
  }>;
  screenshots?: string[];
  finalScreenshot?: string;
  error?: string;
}

interface SkopaqObserveResponse {
  success?: boolean;  // Optional - Cloudflare fallback doesn't include this
  actions?: Array<{
    description: string;
    selector: string;
    type: string;
    confidence: number;
    method?: string;    // Cloudflare format
    arguments?: unknown[];  // Cloudflare format
  }>;
  elements?: Array<{   // Cloudflare fallback format
    tag: string;
    text: string;
    selector: string;
    attributes?: Record<string, string>;
  }>;
  error?: string;
  _backend?: string;   // Cloudflare includes this
}

interface SkopaqExtractResponse {
  success: boolean;
  data?: Record<string, unknown>;
  error?: string;
}

interface SkopaqAgentResponse {
  success: boolean;
  completed: boolean;
  message?: string;
  actions?: Array<{
    action: string;
    success: boolean;
    screenshot?: string;
  }>;
  screenshots?: string[];
  usage?: {
    inputTokens: number;
    outputTokens: number;
  };
  error?: string;
}

// MCP Content types
type TextContent = {
  type: "text";
  text: string;
};

type ImageContent = {
  type: "image";
  data: string;
  mimeType: string;
};

type McpContent = TextContent | ImageContent;

// Helper to call Browser Pool API (primary) with Cloudflare fallback
// Now with production-grade JWT authentication and user context
async function callWorkerAPI<T>(
  endpoint: string,
  body: Record<string, unknown>,
  env: Env,
  userContext?: UserContext
): Promise<T> {
  // Primary: Vultr VKE Browser Pool (if configured)
  const poolUrl = env.BROWSER_POOL_URL;
  // Fallback: Cloudflare Browser Rendering
  const fallbackUrl = env.ARGUS_API_URL || "https://skopaq-api.samuelvinay-kumar.workers.dev";

  // Try Browser Pool first if configured
  if (poolUrl) {
    try {
      console.log(`[DEBUG] Attempting Browser Pool: ${poolUrl}${endpoint}`);
      const poolHeaders: Record<string, string> = {
        "Content-Type": "application/json",
      };

      // Production: Sign JWT with user context
      if (env.BROWSER_POOL_JWT_SECRET) {
        console.log(`[DEBUG] Signing JWT with secret (length: ${env.BROWSER_POOL_JWT_SECRET.length})`);
        const token = await signPoolToken({
          iss: "argus-mcp",
          sub: userContext?.userId || "mcp-anonymous",
          aud: "browser-pool",
          org_id: userContext?.orgId,
          email: userContext?.email,
          action: endpoint.replace("/", ""),
          ip: userContext?.ip,
        }, env.BROWSER_POOL_JWT_SECRET);
        poolHeaders["Authorization"] = `Bearer ${token}`;
        console.log(`[DEBUG] JWT signed, token length: ${token.length}`);
      }
      // Legacy fallback: Use static API key (deprecated)
      else if (env.BROWSER_POOL_API_KEY) {
        console.warn("DEPRECATION: Using legacy API key. Configure BROWSER_POOL_JWT_SECRET.");
        poolHeaders["Authorization"] = `Bearer ${env.BROWSER_POOL_API_KEY}`;
      } else {
        console.warn("[DEBUG] No auth configured for Browser Pool!");
      }

      console.log(`[DEBUG] Fetching ${poolUrl}${endpoint}`);
      const response = await fetch(`${poolUrl}${endpoint}`, {
        method: "POST",
        headers: poolHeaders,
        body: JSON.stringify(body),
      });
      console.log(`[DEBUG] Browser Pool response: ${response.status}`);

      if (response.ok) {
        return response.json() as Promise<T>;
      }

      // Pool failed, log and fall through to fallback
      const errorText = await response.text();
      console.warn(`Browser Pool failed (${response.status}): ${errorText}, falling back to Cloudflare`);
    } catch (error) {
      console.warn(`Browser Pool error: ${error}, falling back to Cloudflare`);
    }
  } else {
    console.log(`[DEBUG] No BROWSER_POOL_URL configured, using fallback`);
  }

  // Fallback headers (for Cloudflare/Skopaq API)
  const fallbackHeaders: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (env.API_TOKEN) {
    fallbackHeaders["Authorization"] = `Bearer ${env.API_TOKEN}`;
  }

  // Fallback to Cloudflare Browser Rendering
  const response = await fetch(`${fallbackUrl}${endpoint}`, {
    method: "POST",
    headers: fallbackHeaders,
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Browser API error (${response.status}): ${errorText}`);
  }

  return response.json() as Promise<T>;
}

// Helper to call Brain API (intelligence)
async function callBrainAPI<T>(
  endpoint: string,
  method: "GET" | "POST" | "PUT" | "DELETE" = "POST",
  body?: Record<string, unknown>,
  env?: Env,
  accessToken?: string,
  maxRetries: number = 3,
): Promise<T> {
  const brainUrl = env?.ARGUS_BRAIN_URL || "https://skopaq-brain-production.up.railway.app";

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  // Add Authorization header if access token is provided
  if (accessToken) {
    headers["Authorization"] = `Bearer ${accessToken}`;
  }

  const fetchOptions: RequestInit = {
    method,
    headers,
  };

  if (body && (method === "POST" || method === "PUT")) {
    fetchOptions.body = JSON.stringify(body);
  }

  // Retry loop with exponential backoff for rate limits
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const response = await fetch(`${brainUrl}${endpoint}`, fetchOptions);

    if (response.status === 429 && attempt < maxRetries) {
      // Rate limited — respect Retry-After header or use exponential backoff
      const retryAfter = response.headers.get("Retry-After");
      const delayMs = retryAfter
        ? parseInt(retryAfter, 10) * 1000
        : Math.min(1000 * Math.pow(2, attempt), 16000);
      console.log(`[Brain API] Rate limited on ${endpoint}, retrying in ${delayMs}ms (attempt ${attempt + 1}/${maxRetries})`);
      await new Promise(r => setTimeout(r, delayMs));
      continue;
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Brain API error (${response.status}): ${errorText}`);
    }

    return response.json() as Promise<T>;
  }

  throw new Error(`Brain API rate limited after ${maxRetries} retries: ${endpoint}`);
}

// Helper to register MCP connection with Brain API
async function registerMCPConnection(
  env: Env,
  accessToken: string,
  sessionId: string,
  clientName?: string
): Promise<string | null> {
  try {
    const brainUrl = env?.ARGUS_BRAIN_URL || "https://skopaq-brain-production.up.railway.app";
    const response = await fetch(`${brainUrl}/api/v1/mcp/connections/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
      },
      body: JSON.stringify({
        session_id: sessionId,
        client_id: 'argus-mcp',
        client_name: clientName || 'MCP Client',
        client_type: 'mcp',
      }),
    });

    if (response.ok) {
      const data = await response.json() as { connection_id: string };
      console.log(`[MCP] Connection registered: ${data.connection_id}`);
      return data.connection_id;
    }
    console.warn(`[MCP] Failed to register connection: ${response.status}`);
    return null;
  } catch (error) {
    console.error('[MCP] Connection registration error:', error);
    return null;
  }
}

// Alias for backward compatibility
const callSkopaqAPI = callWorkerAPI;

// Helper to record MCP activity after tool executions
async function recordMCPActivity(
  env: Env,
  accessToken: string,
  connectionId: string,
  toolName: string,
  options: {
    durationMs?: number;
    success?: boolean;
    errorMessage?: string;
    screenshotKey?: string;
    inputTokens?: number;
    outputTokens?: number;
    metadata?: Record<string, unknown>;
  }
): Promise<void> {
  try {
    await fetch(`${env.ARGUS_BRAIN_URL}/api/v1/mcp/connections/activity`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
      },
      body: JSON.stringify({
        connection_id: connectionId,
        tool_name: toolName,
        request_id: crypto.randomUUID(),
        duration_ms: options.durationMs,
        success: options.success ?? true,
        error_message: options.errorMessage,
        screenshot_key: options.screenshotKey,
        input_tokens: options.inputTokens,
        output_tokens: options.outputTokens,
        metadata: options.metadata,
      }),
    });
  } catch (error) {
    console.error('[MCP] Activity recording error:', error);
    // Don't throw - activity recording should not block tool execution
  }
}

// Interface for KV namespace
interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

// Extend Env to include KV namespace
interface EnvWithKV extends Env {
  AUTH_STATE?: KVNamespace;
}

// Create MCP Server with Skopaq tools
export class SkopaqMcpAgentSQLite extends McpAgent<EnvWithKV> {
  server = new McpServer({
    name: "Skopaq E2E Testing Agent",
    version: "1.0.0",
  });

  /**
   * Get the stored access token from KV or DO storage
   * Returns undefined if not authenticated or token expired
   */
  async getAccessToken(): Promise<string | undefined> {
    try {
      // First check DO storage for direct auth
      const authStr = await this.ctx.storage.get<string>("auth");
      if (authStr) {
        const auth = JSON.parse(authStr);
        if (auth.access_token && auth.expires_at) {
          if (new Date(auth.expires_at) > new Date()) {
            return auth.access_token;
          }
        }
      }

      // Check for pending auth that might have been completed via KV
      if (this.env.AUTH_STATE) {
        const pendingAuthStr = await this.ctx.storage.get<string>("pending_auth");
        if (pendingAuthStr) {
          const pendingAuth = JSON.parse(pendingAuthStr);
          if (pendingAuth.user_code) {
            const kvAuthStr = await this.env.AUTH_STATE.get(`auth_${pendingAuth.user_code}`);
            if (kvAuthStr) {
              const kvAuth = JSON.parse(kvAuthStr);
              if (kvAuth.status === "completed" && kvAuth.access_token) {
                // Token found in KV, verify expiry
                if (kvAuth.expires_at && new Date(kvAuth.expires_at) > new Date()) {
                  // Save to DO storage for future use
                  await this.ctx.storage.put("auth", JSON.stringify({
                    access_token: kvAuth.access_token,
                    expires_at: kvAuth.expires_at,
                    user_id: kvAuth.user_id,
                  }));
                  return kvAuth.access_token;
                }
              }
            }
          }
        }
      }

      return undefined;
    } catch (error) {
      console.error("Error getting access token:", error);
      return undefined;
    }
  }

  /**
   * Wrapper for callBrainAPI that automatically injects the access token
   * This is the primary method tools should use for Brain API calls
   */
  async callBrainAPIWithAuth<T>(
    endpoint: string,
    method: "GET" | "POST" | "PUT" | "DELETE" = "POST",
    body?: Record<string, unknown>
  ): Promise<T> {
    const accessToken = await this.getAccessToken();
    return callBrainAPI<T>(endpoint, method, body, this.env, accessToken);
  }

  /**
   * Check if user is authenticated, throw helpful error if not
   */
  async requireAuth(): Promise<string> {
    const accessToken = await this.getAccessToken();
    if (!accessToken) {
      throw new Error("AUTH_REQUIRED");
    }
    return accessToken;
  }

  /**
   * Get the stored MCP connection ID from DO storage
   * Returns undefined if not connected
   */
  async getConnectionId(): Promise<string | undefined> {
    try {
      const connectionStr = await this.ctx.storage.get<string>("mcp_connection");
      if (connectionStr) {
        const connection = JSON.parse(connectionStr);
        return connection.connection_id;
      }
      return undefined;
    } catch (error) {
      console.error("Error getting connection ID:", error);
      return undefined;
    }
  }

  /**
   * Record activity for a tool execution (non-blocking)
   */
  async recordActivity(
    toolName: string,
    options: {
      durationMs?: number;
      success?: boolean;
      errorMessage?: string;
      screenshotKey?: string;
      inputTokens?: number;
      outputTokens?: number;
      metadata?: Record<string, unknown>;
    }
  ): Promise<void> {
    const accessToken = await this.getAccessToken();
    const connectionId = await this.getConnectionId();

    if (accessToken && connectionId) {
      // Fire and forget - don't await
      recordMCPActivity(this.env, accessToken, connectionId, toolName, options);
    }
  }

  /**
   * Handle common error patterns including auth requirement
   */
  handleError(error: unknown): { content: Array<{ type: "text"; text: string }>; isError: true } {
    const message = error instanceof Error ? error.message : "Unknown error";
    
    if (message === "AUTH_REQUIRED") {
      return {
        content: [{
          type: "text" as const,
          text: `## Authentication Required\n\nPlease run \`argus_auth\` first to sign in to Skopaq.\n\n**Steps:**\n1. Run \`argus_auth\` to get a verification code\n2. Open the URL and sign in\n3. Run \`argus_auth_complete\` to finish authentication`,
        }],
        isError: true,
      };
    }

    // Check for 401/403 errors from API
    if (message.includes("401") || message.includes("403") || message.includes("Unauthorized") || message.includes("authentication")) {
      return {
        content: [{
          type: "text" as const,
          text: `## Authentication Error\n\nYour session may have expired. Please run \`argus_auth\` to sign in again.\n\n**Error:** ${message}`,
        }],
        isError: true,
      };
    }

    return {
      content: [{
        type: "text" as const,
        text: `Error: ${message}`,
      }],
      isError: true,
    };
  }

  /**
   * Helper to create an auth required response
   */
  authRequiredResponse() {
    return {
      content: [{
        type: "text" as const,
        text: `## Authentication Required\n\nPlease run \`argus_auth\` first to sign in to Skopaq.\n\n**Steps:**\n1. Run \`argus_auth\` to get a verification code\n2. Open the URL and sign in\n3. Run \`argus_auth_complete\` to finish authentication`,
      }],
      isError: true,
    };
  }

  async init() {
    // =========================================================================
    // AUTHENTICATION TOOLS - OAuth2 Device Flow
    // =========================================================================

    // Tool: argus_auth - Start authentication flow
    this.server.tool(
      "argus_auth",
      "Authenticate with Skopaq to access protected features like projects, quality intelligence, and team collaboration. Opens a browser for secure sign-in.",
      {},
      async () => {
        try {
          // Call Brain API to start device auth flow (uses form-urlencoded)
          const response = await fetch(
            `${this.env.ARGUS_BRAIN_URL || "https://skopaq-brain-production.up.railway.app"}/api/v1/auth/device/authorize`,
            {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                client_id: "argus-mcp-server",
                scope: "read write",
              }).toString(),
            }
          );

          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to start auth: ${errorText}`);
          }

          const data = await response.json() as {
            device_code: string;
            user_code: string;
            verification_uri: string;
            verification_uri_complete: string;
            expires_in: number;
          };

          // Store pending auth in DO storage
          await this.ctx.storage.put("pending_auth", JSON.stringify({
            device_code: data.device_code,
            user_code: data.user_code,
            expires_at: new Date(Date.now() + data.expires_in * 1000).toISOString(),
          }));

          // Also store in KV for cross-session access
          if (this.env.AUTH_STATE) {
            await this.env.AUTH_STATE.put(`auth_${data.user_code}`, JSON.stringify({
              device_code: data.device_code,
              status: "pending",
              created_at: new Date().toISOString(),
            }), { expirationTtl: data.expires_in });
          }

          return {
            content: [{
              type: "text" as const,
              text: `## Skopaq Authentication\n\n**Your verification code:** \`${data.user_code}\`\n\n**Steps to sign in:**\n1. Open this URL in your browser:\n   ${data.verification_uri_complete}\n\n2. Sign in with your Skopaq account\n\n3. Enter the code if prompted: \`${data.user_code}\`\n\n4. After signing in, run \`argus_auth_complete\` to finish\n\n*Code expires in ${Math.floor(data.expires_in / 60)} minutes*`,
            }],
          };
        } catch (error) {
          return {
            content: [{
              type: "text" as const,
              text: `Error starting authentication: ${error instanceof Error ? error.message : "Unknown error"}`,
            }],
            isError: true,
          };
        }
      }
    );

    // Tool: argus_auth_complete - Complete authentication flow
    this.server.tool(
      "argus_auth_complete",
      "Complete the authentication flow after signing in via browser. Call this after you've entered the code on the Skopaq website.",
      {},
      async () => {
        try {
          // Get pending auth from DO storage
          const pendingAuthStr = await this.ctx.storage.get<string>("pending_auth");
          
          let pendingAuth: { device_code: string; user_code: string; expires_at: string } | null = null;
          
          if (pendingAuthStr) {
            pendingAuth = JSON.parse(pendingAuthStr);
          }

          // If not in DO storage, try KV
          if (!pendingAuth && this.env.AUTH_STATE) {
            // We need the user_code to look up in KV, but we don't have it
            // This is a limitation - user needs to start fresh if session was lost
          }

          if (!pendingAuth) {
            return {
              content: [{
                type: "text" as const,
                text: `## No Pending Authentication\n\nPlease run \`argus_auth\` first to start the authentication flow.`,
              }],
              isError: true,
            };
          }

          // Check if expired
          if (new Date(pendingAuth.expires_at) < new Date()) {
            await this.ctx.storage.delete("pending_auth");
            return {
              content: [{
                type: "text" as const,
                text: `## Authentication Expired\n\nYour verification code has expired. Please run \`argus_auth\` again to get a new code.`,
              }],
              isError: true,
            };
          }

          // Poll the token endpoint (uses form-urlencoded)
          const response = await fetch(
            `${this.env.ARGUS_BRAIN_URL || "https://skopaq-brain-production.up.railway.app"}/api/v1/auth/device/token`,
            {
              method: "POST",
              headers: { "Content-Type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                client_id: "argus-mcp-server",
                device_code: pendingAuth.device_code,
                grant_type: "urn:ietf:params:oauth:grant-type:device_code",
              }).toString(),
            }
          );

          const data = await response.json() as {
            access_token?: string;
            expires_in?: number;
            error?: string;
            error_description?: string;
            user_id?: string;
          };

          if (data.error) {
            if (data.error === "authorization_pending") {
              return {
                content: [{
                  type: "text" as const,
                  text: `## Waiting for Authorization\n\nPlease complete sign-in at the Skopaq website, then run \`argus_auth_complete\` again.\n\n**Your code:** \`${pendingAuth.user_code}\``,
                }],
              };
            }
            throw new Error(data.error_description || data.error);
          }

          if (!data.access_token) {
            throw new Error("No access token received");
          }

          // Store the auth tokens in DO storage
          const authData = {
            access_token: data.access_token,
            expires_at: new Date(Date.now() + (data.expires_in || 3600) * 1000).toISOString(),
            user_id: data.user_id,
          };
          await this.ctx.storage.put("auth", JSON.stringify(authData));

          // Also update KV
          if (this.env.AUTH_STATE) {
            await this.env.AUTH_STATE.put(`auth_${pendingAuth.user_code}`, JSON.stringify({
              ...authData,
              status: "completed",
            }), { expirationTtl: data.expires_in || 3600 });
          }

          // Clear pending auth
          await this.ctx.storage.delete("pending_auth");

          // Register the MCP connection with the Brain API
          const sessionId = generateSessionId();
          const connectionId = await registerMCPConnection(
            this.env,
            data.access_token,
            sessionId,
            'Claude Code MCP'
          );

          // Store connection_id in DO storage if registration succeeded
          if (connectionId) {
            await this.ctx.storage.put("mcp_connection", JSON.stringify({
              connection_id: connectionId,
              session_id: sessionId,
              registered_at: new Date().toISOString(),
            }));
          }

          return {
            content: [{
              type: "text" as const,
              text: `## Authentication Successful!\n\nYou are now signed in to Skopaq.\n\n**You can now use:**\n- \`argus_projects\` - List your projects\n- \`argus_events\` - View production errors\n- \`argus_dashboard\` - Get project overview\n- And all other Skopaq tools!\n\n*Session expires in ${Math.floor((data.expires_in || 3600) / 60)} minutes*`,
            }],
          };
        } catch (error) {
          return {
            content: [{
              type: "text" as const,
              text: `Error completing authentication: ${error instanceof Error ? error.message : "Unknown error"}`,
            }],
            isError: true,
          };
        }
      }
    );

    // Tool: argus_auth_status - Check authentication status
    this.server.tool(
      "argus_auth_status",
      "Check your current authentication status with Skopaq.",
      {},
      async () => {
        try {
          const accessToken = await this.getAccessToken();

          if (!accessToken) {
            return {
              content: [{
                type: "text" as const,
                text: `## Not Authenticated\n\nYou are not currently signed in to Skopaq.\n\nRun \`argus_auth\` to sign in and access protected features.`,
              }],
            };
          }

          // Get auth details
          const authStr = await this.ctx.storage.get<string>("auth");
          const auth = authStr ? JSON.parse(authStr) : {};
          const expiresAt = auth.expires_at ? new Date(auth.expires_at) : null;
          const remainingTime = expiresAt ? Math.floor((expiresAt.getTime() - Date.now()) / 60000) : 0;

          return {
            content: [{
              type: "text" as const,
              text: `## Authenticated\n\nYou are signed in to Skopaq.\n\n**Session info:**\n- User ID: \`${auth.user_id || "Unknown"}\`\n- Expires in: ${remainingTime} minutes\n\n**Available features:**\n- Projects, Events, Tests, Dashboard\n- Quality Intelligence, Risk Scores\n- Self-Healing, Collaboration tools`,
            }],
          };
        } catch (error) {
          return {
            content: [{
              type: "text" as const,
              text: `Error checking auth status: ${error instanceof Error ? error.message : "Unknown error"}`,
            }],
            isError: true,
          };
        }
      }
    );

    // Tool: argus_auth_logout - Sign out from Skopaq
    this.server.tool(
      "argus_auth_logout",
      "Sign out from Skopaq and clear stored credentials.",
      {},
      async () => {
        try {
          // Clear all auth data from DO storage
          await this.ctx.storage.delete("auth");
          await this.ctx.storage.delete("pending_auth");

          return {
            content: [{
              type: "text" as const,
              text: `## Signed Out\n\nYou have been signed out from Skopaq.\n\nRun \`argus_auth\` to sign in again.`,
            }],
          };
        } catch (error) {
          return {
            content: [{
              type: "text" as const,
              text: `Error signing out: ${error instanceof Error ? error.message : "Unknown error"}`,
            }],
            isError: true,
          };
        }
      }
    );

    // =========================================================================
    // CORE TOOLS - Health and basic operations
    // =========================================================================

    // Tool: argus_health - Check Skopaq API status
    this.server.tool(
      "argus_health",
      "Check the health and status of the Skopaq E2E testing API",
      {},
      async () => {
        try {
          const apiUrl = this.env.ARGUS_API_URL || "https://skopaq-api.samuelvinay-kumar.workers.dev";
          const response = await fetch(`${apiUrl}/health`);
          const data = await response.json();

          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(data, null, 2),
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_discover - Discover interactive elements
    this.server.tool(
      "argus_discover",
      "Discover interactive elements and possible actions on a web page. Returns clickable buttons, links, form inputs, and other actionable elements.",
      {
        url: z.string().url().describe("The URL of the page to analyze"),
        instruction: z.string().optional().describe("What to look for (e.g., 'Find all buttons', 'Find the login form')"),
      },
      async ({ url, instruction }) => {
        try {
          const result = await callSkopaqAPI<SkopaqObserveResponse>("/observe", {
            url,
            instruction: instruction || "What actions can I take on this page?",
          }, this.env);

          // Handle both Browser Pool format (success: true) and Cloudflare format (no success field)
          const hasData = result.actions?.length || result.elements?.length;
          if (result.success === false || (!hasData && result.error)) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Discovery failed: ${result.error || "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }

          // Format the discovered actions (handle both formats)
          let formattedActions: string;
          if (result.actions?.length) {
            formattedActions = result.actions.map((action, i) =>
              `${i + 1}. ${action.description}\n   Selector: \`${action.selector}\`\n   Type: ${action.type || action.method || 'action'}${action.confidence ? `\n   Confidence: ${(action.confidence * 100).toFixed(0)}%` : ''}`
            ).join("\n\n");
          } else if (result.elements?.length) {
            // Cloudflare fallback format
            formattedActions = result.elements.map((el, i) =>
              `${i + 1}. ${el.text || el.tag}\n   Selector: \`${el.selector}\`\n   Type: ${el.tag}${el.attributes?.href ? `\n   Link: ${el.attributes.href}` : ''}`
            ).join("\n\n");
          } else {
            formattedActions = "No actions discovered";
          }

          return {
            content: [
              {
                type: "text" as const,
                text: `## Discovered Elements on ${url}\n\n${formattedActions}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_act - Execute browser action
    this.server.tool(
      "argus_act",
      "Execute a browser action like clicking, typing, or navigating. Uses AI to find the right element based on natural language.",
      {
        url: z.string().url().describe("The URL of the page"),
        instruction: z.string().describe("What action to perform (e.g., 'Click the login button', 'Type \"hello\" in the search box')"),
        selfHeal: z.boolean().optional().describe("Enable self-healing selectors (default: true)"),
        screenshot: z.boolean().optional().describe("Capture a screenshot after the action (default: true)"),
      },
      async ({ url, instruction, selfHeal = true, screenshot = true }) => {
        const startTime = Date.now();
        try {
          const sessionId = generateSessionId();

          const result = await callSkopaqAPI<SkopaqActResponse>("/act", {
            url,
            instruction,
            selfHeal,
            screenshot,
          }, this.env);

          if (!result.success) {
            // Record failed activity - use error, message, or fallback
            const errorMsg = result.error || result.message || "Unknown error";
            this.recordActivity("argus_act", {
              durationMs: Date.now() - startTime,
              success: false,
              errorMessage: errorMsg,
              metadata: { url, instruction },
            });

            return {
              content: [
                {
                  type: "text" as const,
                  text: `Action failed: ${errorMsg}`,
                },
              ],
              isError: true,
            };
          }

          // Store screenshot in R2 if available
          let screenshotUrl: string | undefined;
          let screenshotKey: string | undefined;
          if (result.screenshot) {
            const uploaded = await storeScreenshot(
              this.env,
              result.screenshot,
              sessionId,
              "action",
              { instruction, url }
            );
            screenshotUrl = uploaded.url;
            screenshotKey = uploaded.key;
          }

          // Build screenshot section
          const screenshotSection = screenshotUrl
            ? `\n\n### Screenshot:\n[View Screenshot](${screenshotUrl})`
            : "";

          // Record successful activity
          this.recordActivity("argus_act", {
            durationMs: Date.now() - startTime,
            success: true,
            screenshotKey,
            metadata: { url, instruction, sessionId },
          });

          return {
            content: [
              {
                type: "text" as const,
                text: `## Action Result\n\n**Session ID:** ${sessionId}\n\n${result.message || "Action completed successfully"}\n\n### Actions Performed:\n${result.actions?.map(a => `- ${a.action}${a.selector ? ` on \`${a.selector}\`` : ""}${a.value ? ` with value "${a.value}"` : ""}: ${a.success ? "Success" : "Failed"}`).join("\n") || "None"}${screenshotSection}`,
              },
            ],
          };
        } catch (error) {
          // Record error activity
          this.recordActivity("argus_act", {
            durationMs: Date.now() - startTime,
            success: false,
            errorMessage: error instanceof Error ? error.message : "Unknown error",
            metadata: { url, instruction },
          });

          return this.handleError(error);
        }
      }
    );

    // Tool: argus_test - Run multi-step E2E test
    this.server.tool(
      "argus_test",
      "Run a multi-step E2E test on a web application. Executes a sequence of test steps and captures screenshots at each step. Returns detailed results including pass/fail status for each step.",
      {
        url: z.string().url().describe("The starting URL for the test"),
        steps: z.array(z.string()).min(1).describe("Array of test step instructions (e.g., ['Click the login button', 'Type \"user@example.com\" in email field', 'Click submit'])"),
        browser: z.enum(["chrome", "firefox", "safari", "edge"]).optional().describe("Browser to use (default: chrome)"),
      },
      async ({ url, steps, browser = "chrome" }) => {
        const startTime = Date.now();
        try {
          const sessionId = generateSessionId();

          const result = await callSkopaqAPI<SkopaqTestResponse>("/test", {
            url,
            steps,
            browser,
            captureScreenshots: true,
          }, this.env);

          // Format step results
          const stepResults = result.steps?.map((step, i) => {
            const status = step.success ? "PASS" : "FAIL";
            const error = step.error ? `\n   Error: ${step.error}` : "";
            return `${i + 1}. [${status}] ${step.instruction}${error}`;
          }).join("\n") || "No steps executed";

          const overallStatus = result.success ? "PASSED" : "FAILED";
          const passedSteps = result.steps?.filter(s => s.success).length || 0;
          const totalSteps = result.steps?.length || 0;

          // Store screenshots in R2 and get URLs
          const screenshotUrls: string[] = [];
          const screenshotKeys: string[] = [];
          let finalScreenshotUrl: string | undefined;
          let finalScreenshotKey: string | undefined;

          // Store step screenshots if available
          if (result.steps) {
            for (let i = 0; i < result.steps.length; i++) {
              const step = result.steps[i];
              if (step.screenshot) {
                const uploaded = await storeScreenshot(
                  this.env,
                  step.screenshot,
                  sessionId,
                  i,
                  { stepName: step.instruction, url }
                );
                if (uploaded.url) {
                  screenshotUrls.push(uploaded.url);
                }
                if (uploaded.key) {
                  screenshotKeys.push(uploaded.key);
                }
              }
            }
          }

          // Store final screenshot
          if (result.finalScreenshot) {
            const uploaded = await storeScreenshot(
              this.env,
              result.finalScreenshot,
              sessionId,
              "final",
              { type: "final", url }
            );
            finalScreenshotUrl = uploaded.url;
            finalScreenshotKey = uploaded.key;
          }

          // Build screenshot section for response
          let screenshotSection = "";
          if (screenshotUrls.length > 0 || finalScreenshotUrl) {
            screenshotSection = "\n\n### Screenshots:";
            screenshotUrls.forEach((screenshotUrl, i) => {
              screenshotSection += `\n${i + 1}. [Step ${i + 1}](${screenshotUrl})`;
            });
            if (finalScreenshotUrl) {
              screenshotSection += `\n- [Final Screenshot](${finalScreenshotUrl})`;
            }
          }

          // Record activity
          this.recordActivity("argus_test", {
            durationMs: Date.now() - startTime,
            success: result.success,
            errorMessage: result.success ? undefined : result.error,
            screenshotKey: finalScreenshotKey || screenshotKeys[screenshotKeys.length - 1],
            metadata: {
              url,
              browser,
              sessionId,
              totalSteps,
              passedSteps,
              stepCount: steps.length,
            },
          });

          return {
            content: [
              {
                type: "text" as const,
                text: `## Test Results: ${overallStatus}\n\n**Session ID:** ${sessionId}\n**Browser:** ${browser}\n**URL:** ${url}\n**Steps:** ${passedSteps}/${totalSteps} passed\n\n### Step Details:\n${stepResults}${screenshotSection}`,
              },
            ],
          };
        } catch (error) {
          // Record error activity
          this.recordActivity("argus_test", {
            durationMs: Date.now() - startTime,
            success: false,
            errorMessage: error instanceof Error ? error.message : "Unknown error",
            metadata: { url, browser, stepCount: steps.length },
          });

          return this.handleError(error);
        }
      }
    );

    // Tool: argus_extract - Extract data from page
    this.server.tool(
      "argus_extract",
      "Extract structured data from a web page using AI. Can extract specific information like product details, prices, user information, etc.",
      {
        url: z.string().url().describe("The URL of the page to extract data from"),
        instruction: z.string().describe("What data to extract (e.g., 'Extract all product names and prices', 'Get the user profile information')"),
        schema: z.record(z.string()).optional().describe("Expected data schema as key-value pairs (optional)"),
      },
      async ({ url, instruction, schema }) => {
        try {
          const result = await callSkopaqAPI<SkopaqExtractResponse>("/extract", {
            url,
            instruction,
            schema: schema || {},
          }, this.env);

          if (!result.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Extraction failed: ${result.error || "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }

          // Handle case where data is undefined or null
          const extractedData = result.data ?? {};
          return {
            content: [
              {
                type: "text" as const,
                text: `## Extracted Data from ${url}\n\n\`\`\`json\n${JSON.stringify(extractedData, null, 2)}\n\`\`\``,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_agent - Autonomous task completion
    this.server.tool(
      "argus_agent",
      "Run an autonomous AI agent to complete a complex task on a website. The agent will navigate, click, type, and perform multiple actions to achieve the goal.",
      {
        url: z.string().url().describe("The starting URL"),
        instruction: z.string().describe("The task to complete (e.g., 'Sign up for a new account with email test@example.com', 'Add the first product to cart and proceed to checkout')"),
        maxSteps: z.number().min(1).max(30).optional().describe("Maximum number of steps to take (default: 10)"),
      },
      async ({ url, instruction, maxSteps = 10 }) => {
        const startTime = Date.now();
        try {
          const sessionId = generateSessionId();

          const result = await callSkopaqAPI<SkopaqAgentResponse>("/agent", {
            url,
            instruction,
            maxSteps,
            captureScreenshots: true,
          }, this.env);

          const status = result.success && result.completed ? "COMPLETED" : result.success ? "IN PROGRESS" : "FAILED";

          // Format actions taken
          const actionsList = result.actions?.map((action, i) => {
            const icon = action.success ? "+" : "-";
            return `${i + 1}. [${icon}] ${action.action}`;
          }).join("\n") || "No actions recorded";

          // Store all screenshots in R2
          const screenshotUrls: string[] = [];
          const screenshotKeys: string[] = [];
          if (result.screenshots && result.screenshots.length > 0) {
            for (let i = 0; i < result.screenshots.length; i++) {
              const uploaded = await storeScreenshot(
                this.env,
                result.screenshots[i],
                sessionId,
                i,
                { step: String(i), url }
              );
              if (uploaded.url) {
                screenshotUrls.push(uploaded.url);
              }
              if (uploaded.key) {
                screenshotKeys.push(uploaded.key);
              }
            }
          }

          // Build screenshot section
          let screenshotSection = "";
          if (screenshotUrls.length > 0) {
            screenshotSection = "\n\n### Screenshots:";
            screenshotUrls.forEach((screenshotUrl, i) => {
              screenshotSection += `\n${i + 1}. [Step ${i + 1}](${screenshotUrl})`;
            });
          }

          // Record activity
          this.recordActivity("argus_agent", {
            durationMs: Date.now() - startTime,
            success: result.success,
            errorMessage: result.success ? undefined : result.error,
            screenshotKey: screenshotKeys[screenshotKeys.length - 1],
            inputTokens: result.usage?.inputTokens,
            outputTokens: result.usage?.outputTokens,
            metadata: {
              url,
              instruction,
              sessionId,
              maxSteps,
              actionsTaken: result.actions?.length || 0,
              completed: result.completed,
            },
          });

          return {
            content: [
              {
                type: "text" as const,
                text: `## Agent Task: ${status}\n\n**Session ID:** ${sessionId}\n**Goal:** ${instruction}\n**Starting URL:** ${url}\n**Steps taken:** ${result.actions?.length || 0}/${maxSteps}\n\n### Actions:\n${actionsList}\n\n${result.message ? `**Result:** ${result.message}` : ""}${screenshotSection}`,
              },
            ],
          };
        } catch (error) {
          // Record error activity
          this.recordActivity("argus_agent", {
            durationMs: Date.now() - startTime,
            success: false,
            errorMessage: error instanceof Error ? error.message : "Unknown error",
            metadata: { url, instruction, maxSteps },
          });

          return this.handleError(error);
        }
      }
    );

    // Tool: argus_generate_test - Generate test from natural language (Brain)
    this.server.tool(
      "argus_generate_test",
      "Generate E2E test steps from a natural language description. Uses AI Brain service to create a comprehensive test plan with steps and assertions.",
      {
        url: z.string().url().describe("The URL of the application to test"),
        description: z.string().describe("Description of what the test should verify (e.g., 'Verify user can log in with valid credentials', 'Test the checkout flow with a product')"),
      },
      async ({ url, description }) => {
        try {
          await this.requireAuth();
          // Call Brain to generate test from natural language
          const result = await this.callBrainAPIWithAuth<BrainTestCreateResponse>(
            "/api/v1/tests/create",
            "POST",
            {
              description,
              app_url: url,
            }
          );

          if (!result.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Could not generate test. Try using argus_discover first to understand the page.`,
                },
              ],
              isError: true,
            };
          }

          // Format the generated test
          const stepsText = result.test.steps.map((s, i) =>
            `${i + 1}. ${s.action}${s.target ? ` on "${s.target}"` : ""}${s.value ? ` with "${s.value}"` : ""}`
          ).join("\n");

          const assertionsText = result.test.assertions.map((a, i) =>
            `${i + 1}. ${a.type}${a.target ? ` "${a.target}"` : ""}${a.expected ? ` = "${a.expected}"` : ""}`
          ).join("\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Generated Test: ${result.test.name}\n\n**Target:** ${url}\n**Description:** ${result.test.description}\n\n### Test Steps:\n${stepsText}\n\n### Assertions:\n${assertionsText}\n\n**Tip:** Use \`argus_test\` with these steps to run the test.`,
              },
            ],
          };
        } catch (error) {
          // Fall back to Worker-based discovery if Brain fails
          try {
            const observeResult = await callSkopaqAPI<SkopaqObserveResponse>("/observe", {
              url,
              instruction: "List all interactive elements and their purposes",
            }, this.env);

            const pageContext = observeResult.actions?.map(a => `- ${a.description} (${a.type})`).join("\n") || "No elements found";

            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Test Plan (Discovery Mode)\n\n**Target:** ${url}\n**Objective:** ${description}\n\n### Discovered Page Elements:\n${pageContext}\n\n### Suggested Test Steps:\n1. Navigate to the page\n2. [Create steps based on the discovered elements]\n\n**Note:** Brain service unavailable. Use \`argus_test\` to run manually created steps.`,
                },
              ],
            };
          } catch (fallbackError) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Error generating test: ${error instanceof Error ? error.message : "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }
        }
      }
    );

    // Tool: argus_quality_score - Get quality score for a project (Brain)
    this.server.tool(
      "argus_quality_score",
      "Get the overall quality score and metrics for a project. Shows test coverage, risk level, and production error statistics.",
      {
        project_id: z.string().describe("The project UUID to get quality score for"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<BrainQualityScoreResponse>(
            `/api/v1/quality/score?project_id=${project_id}`,
            "GET",
            
          );

          const riskEmoji = result.risk_level === "high" ? "🔴" : result.risk_level === "medium" ? "🟡" : "🟢";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Quality Score: ${result.quality_score}/100\n\n**Risk Level:** ${riskEmoji} ${result.risk_level.toUpperCase()}\n**Test Coverage:** ${result.test_coverage}%\n\n### Metrics:\n- Total Production Events: ${result.total_events}\n- Generated Tests: ${result.total_tests}\n- Approved Tests: ${result.approved_tests}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_quality_stats - Get detailed quality statistics (Brain)
    this.server.tool(
      "argus_quality_stats",
      "Get detailed quality intelligence statistics including event counts by status, severity breakdown, and test coverage metrics.",
      {
        project_id: z.string().describe("The project UUID to get statistics for"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<BrainQualityStatsResponse>(
            `/api/v1/quality/stats?project_id=${project_id}`,
            "GET",
            
          );

          const stats = result.stats;

          const statusBreakdown = Object.entries(stats.events_by_status)
            .map(([status, count]) => `- ${status}: ${count}`)
            .join("\n");

          const severityBreakdown = Object.entries(stats.events_by_severity)
            .map(([sev, count]) => `- ${sev}: ${count}`)
            .join("\n");

          const testsBreakdown = Object.entries(stats.tests_by_status)
            .map(([status, count]) => `- ${status}: ${count}`)
            .join("\n") || "No tests generated yet";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Quality Intelligence Statistics\n\n### Production Events: ${stats.total_events}\n\n**By Status:**\n${statusBreakdown}\n\n**By Severity:**\n${severityBreakdown}\n\n### Generated Tests: ${stats.total_generated_tests}\n\n**By Status:**\n${testsBreakdown}\n\n**Coverage Rate:** ${stats.coverage_rate}%`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_risk_scores - Calculate and get risk scores (Brain)
    this.server.tool(
      "argus_risk_scores",
      "Calculate risk scores for components and pages based on production errors. Identifies high-risk areas that need more testing.",
      {
        project_id: z.string().describe("The project UUID to calculate risk scores for"),
        calculate: z.boolean().optional().describe("If true, recalculate scores (default: false, just retrieve)"),
      },
      async ({ project_id, calculate = false }) => {
        try {
          await this.requireAuth();
          let result: BrainRiskScoresResponse;

          if (calculate) {
            // Recalculate risk scores
            result = await this.callBrainAPIWithAuth<BrainRiskScoresResponse>(
              "/api/v1/quality/calculate-risk",
              "POST",
              { project_id }
            );
          } else {
            // Just retrieve existing scores
            const response = await this.callBrainAPIWithAuth<{ risk_scores: BrainRiskScoresResponse["risk_scores"] }>(
              `/api/v1/quality/risk-scores?project_id=${project_id}`,
              "GET",
              
            );
            result = { success: true, risk_scores: response.risk_scores, total_entities: response.risk_scores.length };
          }

          if (!result.risk_scores || result.risk_scores.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Risk Scores\n\nNo risk data available yet. Production events need to be ingested via webhooks first.`,
                },
              ],
            };
          }

          const scoresText = result.risk_scores.slice(0, 10).map((score, i) => {
            const emoji = score.overall_score > 70 ? "🔴" : score.overall_score > 40 ? "🟡" : "🟢";
            return `${i + 1}. ${emoji} **${score.entity_identifier}** (${score.entity_type})\n   Score: ${score.overall_score}/100 | Errors: ${score.error_count} | Users affected: ${score.affected_users}`;
          }).join("\n\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Risk Scores (Top ${Math.min(10, result.risk_scores.length)} of ${result.total_entities})\n\n${scoresText}\n\n**Legend:** 🔴 High Risk (>70) | 🟡 Medium Risk (40-70) | 🟢 Low Risk (<40)`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // SYNC TOOLS - Two-way IDE synchronization
    // =========================================================================

    // Tool: argus_sync_push - Push local test changes to Skopaq
    this.server.tool(
      "argus_sync_push",
      "Push local test changes to Skopaq cloud. Syncs test specifications from your IDE to the Skopaq platform for team collaboration and cloud execution.",
      {
        project_id: z.string().describe("The project UUID"),
        test_id: z.string().describe("The test UUID to push"),
        content: z.object({
          id: z.string(),
          name: z.string(),
          description: z.string().optional(),
          steps: z.array(z.object({
            action: z.string(),
            target: z.string().optional(),
            value: z.string().optional(),
          })),
          assertions: z.array(z.object({
            type: z.string(),
            target: z.string().optional(),
            expected: z.string().optional(),
          })).optional(),
          metadata: z.record(z.unknown()).optional(),
        }).describe("The test specification to push"),
        local_version: z.number().describe("Local version number for conflict detection"),
      },
      async ({ project_id, test_id, content, local_version }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<SyncPushResponse>(
            "/api/v1/sync/push",
            "POST",
            {
              project_id,
              test_id,
              content,
              local_version,
              source: "mcp",
            }
          );

          if (!result.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Push failed: ${result.error || "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }

          // Check for conflicts
          if (result.conflicts && result.conflicts.length > 0) {
            const conflictsList = result.conflicts.map((c, i) =>
              `${i + 1}. Test: ${c.test_id}\n   Path: ${c.path.join(".")}\n   Local: ${JSON.stringify(c.local_value)}\n   Remote: ${JSON.stringify(c.remote_value)}`
            ).join("\n\n");

            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Sync Conflicts Detected\n\nPushed ${result.events_pushed} events but ${result.conflicts.length} conflicts need resolution:\n\n${conflictsList}\n\n**Use \`argus_sync_resolve\` to resolve conflicts.**`,
                },
              ],
            };
          }

          return {
            content: [
              {
                type: "text" as const,
                text: `## Push Successful\n\n**Test:** ${test_id}\n**Events pushed:** ${result.events_pushed}\n**New version:** ${result.new_version || "N/A"}\n\nTest is now synced with Skopaq cloud.`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_sync_pull - Pull remote test changes
    this.server.tool(
      "argus_sync_pull",
      "Pull test changes from Skopaq cloud to your local IDE. Fetches the latest test specifications and updates from team members.",
      {
        project_id: z.string().describe("The project UUID to pull tests from"),
        since_version: z.number().optional().describe("Only pull changes since this version (default: 0 for all)"),
        test_id: z.string().optional().describe("Pull specific test only (optional)"),
      },
      async ({ project_id, since_version = 0, test_id }) => {
        try {
          await this.requireAuth();
          const queryParams = new URLSearchParams({
            project_id,
            since_version: since_version.toString(),
          });
          if (test_id) {
            queryParams.set("test_id", test_id);
          }

          const result = await this.callBrainAPIWithAuth<SyncPullResponse>(
            `/api/v1/sync/pull?${queryParams}`,
            "GET"
          );

          if (!result.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Pull failed: ${result.error || "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }

          if (result.events.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## No New Changes\n\nYour local tests are up to date with Skopaq cloud.`,
                },
              ],
            };
          }

          // Format events
          const eventsList = result.events.map((e, i) => {
            const icon = e.type.includes("created") ? "+" : e.type.includes("deleted") ? "-" : "~";
            return `${i + 1}. [${icon}] ${e.type} - Test: ${e.test_id}\n   Time: ${e.timestamp}`;
          }).join("\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Pulled ${result.events.length} Changes\n\n**New version:** ${result.new_version || "N/A"}\n\n### Changes:\n${eventsList}\n\n\`\`\`json\n${JSON.stringify(result.events, null, 2)}\n\`\`\``,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_sync_status - Get sync status
    this.server.tool(
      "argus_sync_status",
      "Get the synchronization status for a project. Shows pending changes, conflicts, and sync state for all tests.",
      {
        project_id: z.string().describe("The project UUID to check status for"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<SyncStatusResponse>(
            `/api/v1/sync/status/${project_id}`,
            "GET",
            
          );

          if (!result.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Could not get sync status. The project may not exist or sync is not initialized.`,
                },
              ],
              isError: true,
            };
          }

          const statusEmoji = result.status === "synced" ? "✅" : result.status === "pending" ? "🔄" : result.status === "conflict" ? "⚠️" : "❌";

          // Format test statuses
          const testsStatus = Object.values(result.tests).map(t => {
            const icon = t.status === "synced" ? "✅" : t.status === "pending" ? "🔄" : "⚠️";
            return `- ${icon} ${t.test_id}: v${t.local_version} (local) / v${t.remote_version} (remote)${t.pending_changes > 0 ? ` - ${t.pending_changes} pending` : ""}${t.conflicts > 0 ? ` - ${t.conflicts} conflicts` : ""}`;
          }).join("\n") || "No tests tracked";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Sync Status: ${statusEmoji} ${result.status.toUpperCase()}\n\n**Project:** ${project_id}\n**Pending changes:** ${result.total_pending}\n**Conflicts:** ${result.total_conflicts}\n\n### Tests:\n${testsStatus}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_sync_resolve - Resolve sync conflicts
    this.server.tool(
      "argus_sync_resolve",
      "Resolve a synchronization conflict between local and remote test versions. Choose to keep local, keep remote, or provide a custom resolution.",
      {
        project_id: z.string().describe("The project UUID"),
        conflict_id: z.string().describe("The conflict ID to resolve"),
        strategy: z.enum(["keep_local", "keep_remote", "merge", "manual"]).describe("Resolution strategy"),
        manual_value: z.unknown().optional().describe("Custom value for manual resolution"),
      },
      async ({ project_id, conflict_id, strategy, manual_value }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<SyncResolveResponse>(
            "/api/v1/sync/resolve",
            "POST",
            {
              project_id,
              conflict_id,
              strategy,
              manual_value,
            }
          );

          if (!result.success || !result.resolved) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Resolution failed: ${result.error || "Could not resolve conflict"}`,
                },
              ],
              isError: true,
            };
          }

          return {
            content: [
              {
                type: "text" as const,
                text: `## Conflict Resolved ✅\n\n**Conflict ID:** ${result.conflict_id}\n**Strategy:** ${strategy}\n**Resolved Value:**\n\`\`\`json\n${JSON.stringify(result.resolved_value, null, 2)}\n\`\`\`\n\nRun \`argus_sync_push\` to sync the resolved changes.`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // EXPORT TOOLS - Multi-language test export
    // =========================================================================

    // Tool: argus_export - Export test to multiple languages
    this.server.tool(
      "argus_export",
      "Export an Skopaq test to executable code in multiple programming languages and frameworks. Supports Python, TypeScript, Java, C#, Ruby, and Go with various testing frameworks.",
      {
        test_id: z.string().describe("The test UUID to export"),
        language: z.enum(["python", "typescript", "java", "csharp", "ruby", "go"]).describe("Target programming language"),
        framework: z.string().describe("Testing framework (e.g., 'playwright', 'selenium', 'cypress', 'puppeteer', 'capybara', 'rod')"),
        options: z.object({
          include_comments: z.boolean().optional().describe("Include explanatory comments"),
          include_assertions: z.boolean().optional().describe("Include assertion code"),
          base_url_variable: z.string().optional().describe("Variable name for base URL"),
          class_name: z.string().optional().describe("Custom test class name"),
        }).optional().describe("Export options"),
      },
      async ({ test_id, language, framework, options = {} }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<ExportResponse>(
            "/api/v1/export/generate",
            "POST",
            {
              test_id,
              language,
              framework,
              options: {
                include_comments: options.include_comments ?? true,
                include_assertions: options.include_assertions ?? true,
                base_url_variable: options.base_url_variable ?? "BASE_URL",
                class_name: options.class_name,
              },
            }
          );

          if (!result.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Export failed: ${result.error || "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }

          const importsSection = result.imports && result.imports.length > 0
            ? `### Required Imports/Dependencies:\n\`\`\`\n${result.imports.join("\n")}\n\`\`\`\n\n`
            : "";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Exported Test: ${result.filename}\n\n**Language:** ${result.language}\n**Framework:** ${result.framework}\n\n${importsSection}### Generated Code:\n\`\`\`${result.language}\n${result.code}\n\`\`\``,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_export_languages - List supported export languages
    this.server.tool(
      "argus_export_languages",
      "List all supported programming languages and testing frameworks for test export.",
      {},
      async () => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<ExportLanguagesResponse>(
            "/api/v1/export/languages",
            "GET",
            
          );

          const languagesList = result.languages.map(l =>
            `### ${l.name} (\`${l.id}\`)\nFrameworks: ${l.frameworks.join(", ")}`
          ).join("\n\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Supported Export Languages\n\n${languagesList}\n\n**Usage:** \`argus_export(test_id, language, framework)\``,
              },
            ],
          };
        } catch (error) {
          // Return static list if API fails
          return {
            content: [
              {
                type: "text" as const,
                text: `## Supported Export Languages\n\n### Python (\`python\`)\nFrameworks: playwright, selenium\n\n### TypeScript (\`typescript\`)\nFrameworks: playwright, puppeteer, cypress\n\n### Java (\`java\`)\nFrameworks: selenium\n\n### C# (\`csharp\`)\nFrameworks: selenium, playwright\n\n### Ruby (\`ruby\`)\nFrameworks: capybara, selenium\n\n### Go (\`go\`)\nFrameworks: rod\n\n**Usage:** \`argus_export(test_id, language, framework)\``,
              },
            ],
          };
        }
      }
    );

    // =========================================================================
    // RECORDING TOOLS - Browser recording to test conversion
    // =========================================================================

    // Tool: argus_recording_to_test - Convert browser recording to test
    this.server.tool(
      "argus_recording_to_test",
      "Convert a browser recording (rrweb format) to an Skopaq test. Analyzes DOM events from recorded sessions and generates executable test steps. Zero AI cost - pure DOM event parsing.",
      {
        recording: z.object({
          events: z.array(z.object({
            type: z.number(),
            data: z.record(z.unknown()),
            timestamp: z.number(),
          })).describe("rrweb event array"),
          metadata: z.object({
            duration: z.number().optional(),
            startTime: z.string().optional(),
            url: z.string().optional(),
          }).optional(),
        }).describe("The rrweb recording data"),
        options: z.object({
          name: z.string().optional().describe("Test name (auto-generated if not provided)"),
          filter_actions: z.array(z.string()).optional().describe("Only include these action types"),
          min_confidence: z.number().optional().describe("Minimum selector confidence (0-1)"),
          deduplicate: z.boolean().optional().describe("Remove duplicate consecutive actions"),
        }).optional(),
      },
      async ({ recording, options = {} }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<RecordingConvertResponse>(
            "/api/v1/recording/convert",
            "POST",
            {
              recording,
              options: {
                name: options.name,
                filter_actions: options.filter_actions,
                min_confidence: options.min_confidence ?? 0.7,
                deduplicate: options.deduplicate ?? true,
              },
            }
          );

          if (!result.success) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `Conversion failed: ${result.error || "Unknown error"}`,
                },
              ],
              isError: true,
            };
          }

          // Format steps
          const stepsText = result.test.steps.map((s, i) =>
            `${i + 1}. ${s.action}${s.target ? ` on "${s.target}"` : ""}${s.value ? ` with "${s.value}"` : ""}`
          ).join("\n");

          const assertionsText = result.test.assertions?.map((a, i) =>
            `${i + 1}. ${a.type}${a.target ? ` "${a.target}"` : ""}${a.expected ? ` = "${a.expected}"` : ""}`
          ).join("\n") || "None generated";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Test Generated from Recording ✨\n\n**Test ID:** ${result.test.id}\n**Name:** ${result.test.name}\n**Source:** ${result.test.source}\n**Recording ID:** ${result.recording_id}\n**Duration:** ${(result.duration_ms / 1000).toFixed(1)}s\n**Events processed:** ${result.events_processed}\n\n### Test Steps (${result.test.steps.length}):\n${stepsText}\n\n### Auto-Generated Assertions:\n${assertionsText}\n\n**Tip:** Use \`argus_test\` to run this test or \`argus_export\` to convert to code.`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_recording_snippet - Get recorder snippet for websites
    this.server.tool(
      "argus_recording_snippet",
      "Generate a JavaScript snippet to record user sessions on any website. The snippet uses rrweb for DOM-based recording that can be converted to tests.",
      {
        project_id: z.string().describe("The project UUID to associate recordings with"),
        options: z.object({
          mask_inputs: z.boolean().optional().describe("Mask sensitive input fields"),
          record_canvas: z.boolean().optional().describe("Record canvas elements"),
          sample_rate: z.number().optional().describe("Sampling rate for mouse movements"),
        }).optional(),
      },
      async ({ project_id, options = {} }) => {
        const snippet = `<!-- Skopaq Session Recorder -->
<script src="https://cdn.jsdelivr.net/npm/rrweb@latest/dist/rrweb.min.js"></script>
<script>
(function() {
  const events = [];
  const projectId = "${project_id}";

  // Start recording
  rrweb.record({
    emit(event) {
      events.push(event);
    },
    maskAllInputs: ${options.mask_inputs ?? true},
    recordCanvas: ${options.record_canvas ?? false},
    sampling: {
      mousemove: ${options.sample_rate ?? 50}
    }
  });

  // Upload recording on page unload or after 5 minutes
  const uploadRecording = () => {
    if (events.length > 0) {
      navigator.sendBeacon(
        ${JSON.stringify(`${this.env.ARGUS_BRAIN_URL || "https://skopaq-brain-production.up.railway.app"}/api/v1/recording/upload`)},
        JSON.stringify({
          project_id: projectId,
          recording: { events, metadata: { url: window.location.href } }
        })
      );
    }
  };

  window.addEventListener("beforeunload", uploadRecording);
  setTimeout(uploadRecording, 300000); // 5 min max

  // Export for manual control
  window.SkopaqRecorder = {
    stop: uploadRecording,
    getEvents: () => events
  };
})();
</script>`;

        return {
          content: [
            {
              type: "text" as const,
              text: `## Skopaq Recording Snippet\n\nAdd this snippet to your website to record user sessions:\n\n\`\`\`html\n${snippet}\n\`\`\`\n\n### Usage:\n1. Add the snippet before \`</body>\`\n2. User sessions are auto-recorded\n3. Use \`argus_recording_to_test\` to convert to tests\n\n### Manual Control:\n- \`window.SkopaqRecorder.stop()\` - Stop and upload\n- \`window.SkopaqRecorder.getEvents()\` - Get events array`,
            },
          ],
        };
      }
    );

    // =========================================================================
    // COLLABORATION TOOLS - Real-time team collaboration
    // =========================================================================

    // Tool: argus_presence - Get/update user presence
    this.server.tool(
      "argus_presence",
      "Get or update user presence information for real-time collaboration. See who else is viewing or editing tests in your workspace.",
      {
        workspace_id: z.string().describe("The workspace UUID"),
        action: z.enum(["get", "join", "leave", "update"]).describe("Presence action"),
        user_id: z.string().optional().describe("User ID (required for join/leave/update)"),
        user_name: z.string().optional().describe("User display name (required for join)"),
        test_id: z.string().optional().describe("Currently viewed test ID"),
        cursor: z.object({
          step_index: z.number().optional(),
          field: z.string().optional(),
        }).optional().describe("Current cursor position"),
      },
      async ({ workspace_id, action, user_id, user_name, test_id, cursor }) => {
        try {
          await this.requireAuth();
          if (action === "get") {
            const result = await this.callBrainAPIWithAuth<PresenceResponse>(
              `/api/v1/collaboration/presence/${workspace_id}`,
              "GET",
              
            );

            if (result.users.length === 0) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: `## Workspace Presence\n\nNo other users currently online in this workspace.`,
                  },
                ],
              };
            }

            const usersList = result.users.map(u => {
              const statusIcon = u.status === "online" ? "🟢" : u.status === "idle" ? "🟡" : "⚫";
              const location = u.test_id ? `viewing ${u.test_id}` : "in workspace";
              return `${statusIcon} **${u.user_name}** - ${location}`;
            }).join("\n");

            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Workspace Presence (${result.users.length} online)\n\n${usersList}`,
                },
              ],
            };
          }

          // Join/Leave/Update actions
          const result = await this.callBrainAPIWithAuth<{ success: boolean }>(
            "/api/v1/collaboration/presence",
            "POST",
            {
              workspace_id,
              action,
              user_id,
              user_name,
              test_id,
              cursor,
            }
          );

          const actionText = action === "join" ? "joined" : action === "leave" ? "left" : "updated presence in";

          return {
            content: [
              {
                type: "text" as const,
                text: `Successfully ${actionText} workspace.`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_comments - Manage test comments
    this.server.tool(
      "argus_comments",
      "Get or add comments on tests for team collaboration. Support for threaded discussions, @mentions, and resolution tracking.",
      {
        test_id: z.string().describe("The test UUID"),
        action: z.enum(["get", "add", "reply", "resolve"]).describe("Comment action"),
        comment_id: z.string().optional().describe("Comment ID (for reply/resolve)"),
        content: z.string().optional().describe("Comment content (for add/reply)"),
        step_index: z.number().optional().describe("Step index to attach comment to"),
        mentions: z.array(z.string()).optional().describe("User IDs to mention"),
      },
      async ({ test_id, action, comment_id, content, step_index, mentions }) => {
        try {
          await this.requireAuth();
          if (action === "get") {
            const result = await this.callBrainAPIWithAuth<CommentsResponse>(
              `/api/v1/collaboration/comments/${test_id}`,
              "GET",
              
            );

            if (result.comments.length === 0) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: `## Test Comments\n\nNo comments on this test yet. Use \`argus_comments\` with action "add" to start a discussion.`,
                  },
                ],
              };
            }

            const commentsList = result.comments.map(c => {
              const resolved = c.resolved ? " ✅" : "";
              const stepRef = c.step_index !== undefined ? ` (Step ${c.step_index + 1})` : "";
              const replies = c.replies && c.replies.length > 0
                ? `\n  └─ ${c.replies.length} replies`
                : "";
              return `- **${c.author_name}**${stepRef}${resolved}: ${c.content}${replies}`;
            }).join("\n");

            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Test Comments (${result.comments.length})\n\n${commentsList}`,
                },
              ],
            };
          }

          // Add/Reply/Resolve actions
          const result = await this.callBrainAPIWithAuth<{ success: boolean; comment_id?: string }>(
            "/api/v1/collaboration/comments",
            "POST",
            {
              test_id,
              action,
              comment_id,
              content,
              step_index,
              mentions,
            }
          );

          const actionText = action === "add" ? "Comment added" : action === "reply" ? "Reply added" : "Comment resolved";

          return {
            content: [
              {
                type: "text" as const,
                text: `${actionText} successfully.${result.comment_id ? ` (ID: ${result.comment_id})` : ""}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // PRODUCTION EVENTS - Query and manage production errors
    // =========================================================================

    // Tool: argus_events - List and filter production events
    this.server.tool(
      "argus_events",
      "List production errors and events that need test coverage. Filter by severity, status, or time range to find what needs attention. This is your window into what's breaking in production.",
      {
        project_id: z.string().describe("The project UUID"),
        status: z.enum(["new", "analyzing", "test_pending_review", "test_generated", "ignored"]).optional().describe("Filter by status"),
        severity: z.enum(["fatal", "error", "warning"]).optional().describe("Filter by severity"),
        source: z.string().optional().describe("Filter by source (sentry, datadog, etc.)"),
        limit: z.number().min(1).max(100).optional().describe("Max results (default: 20)"),
      },
      async ({ project_id, status, severity, source, limit = 20 }) => {
        try {
          await this.requireAuth();
          const params = new URLSearchParams({ project_id, limit: limit.toString() });
          if (status) params.set("status", status);
          if (severity) params.set("severity", severity);
          if (source) params.set("source", source);

          const result = await this.callBrainAPIWithAuth<ProductionEventsResponse>(
            `/api/v1/quality/events?${params}`,
            "GET"
          );

          if (!result.events || result.events.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Production Events\n\nNo events found matching your criteria. Your app is running clean! 🎉\n\n**Tip:** Set up webhooks from Sentry/Datadog to start capturing production errors.`,
                },
              ],
            };
          }

          const eventsList = result.events.map((e, i) => {
            const severityIcon = e.severity === "fatal" ? "🔴" : e.severity === "error" ? "🟠" : "🟡";
            const statusIcon = e.status === "test_generated" ? "✅" : e.status === "test_pending_review" ? "⏳" : "❌";
            return `${i + 1}. ${severityIcon} **${e.title}**\n   Status: ${statusIcon} ${e.status} | Occurrences: ${e.occurrence_count} | Users: ${e.affected_users}\n   Component: ${e.component || "Unknown"} | Source: ${e.source}\n   ID: \`${e.id}\``;
          }).join("\n\n");

          const newCount = result.events.filter(e => e.status === "new").length;
          const summary = newCount > 0 
            ? `⚠️ **${newCount} events need tests!** Use \`argus_test_from_event\` to generate tests.`
            : "All events have been processed.";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Production Events (${result.events.length} found)\n\n${summary}\n\n${eventsList}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_test_from_event - Generate test from production error
    this.server.tool(
      "argus_test_from_event",
      "Generate an E2E test from a specific production error. The AI analyzes the error context, stack trace, and user action to create a comprehensive test that prevents regression.",
      {
        event_id: z.string().describe("The production event UUID to generate test from"),
        project_id: z.string().describe("The project UUID"),
        framework: z.enum(["playwright", "cypress", "jest"]).optional().describe("Test framework (default: playwright)"),
      },
      async ({ event_id, project_id, framework = "playwright" }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{
            success: boolean;
            message: string;
            generated_test?: {
              id: string;
              name: string;
              file_path: string;
              confidence_score: number;
            };
            test_code?: string;
          }>(
            "/api/v1/quality/generate-test",
            "POST",
            {
              production_event_id: event_id,
              project_id,
              framework,
            }
          );

          if (!result.success || !result.generated_test) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Test Generation Failed\n\n${result.message || "Could not generate test from this event."}\n\n**Tip:** Make sure the event has enough context (URL, stack trace, component).`,
                },
              ],
              isError: true,
            };
          }

          const confidenceEmoji = result.generated_test.confidence_score > 0.8 ? "🟢" : result.generated_test.confidence_score > 0.6 ? "🟡" : "🔴";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Test Generated Successfully! 🎉\n\n**Name:** ${result.generated_test.name}\n**File:** \`${result.generated_test.file_path}\`\n**Confidence:** ${confidenceEmoji} ${(result.generated_test.confidence_score * 100).toFixed(0)}%\n**Framework:** ${framework}\n\n### Generated Code:\n\`\`\`typescript\n${result.test_code || "// Code available in the dashboard"}\n\`\`\`\n\n**Next Steps:**\n1. Review the test with \`argus_tests\`\n2. Approve with \`argus_test_review\`\n3. Export to your repo with \`argus_export\``,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_event_triage - AI-powered event triage
    this.server.tool(
      "argus_event_triage",
      "Get AI-powered triage recommendations for production events. Identifies which errors are most critical, suggests groupings, and recommends test priorities.",
      {
        project_id: z.string().describe("The project UUID"),
        limit: z.number().min(1).max(50).optional().describe("Max events to analyze (default: 10)"),
      },
      async ({ project_id, limit = 10 }) => {
        try {
          await this.requireAuth();
          // Get events and risk scores to provide triage recommendations
          const [eventsResult, riskResult] = await Promise.all([
            this.callBrainAPIWithAuth<ProductionEventsResponse>(
              `/api/v1/quality/events?project_id=${project_id}&status=new&limit=${limit}`,
              "GET"
            ),
            this.callBrainAPIWithAuth<BrainRiskScoresResponse>(
              `/api/v1/quality/risk-scores?project_id=${project_id}&limit=10`,
              "GET"
            ),
          ]);

          const events = eventsResult.events || [];
          const riskScores = riskResult.risk_scores || [];

          if (events.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Event Triage\n\n✅ **No untriaged events!** All production errors have been processed.\n\nYour test coverage is keeping production stable.`,
                },
              ],
            };
          }

          // Group events by severity and component
          const fatalEvents = events.filter(e => e.severity === "fatal");
          const errorEvents = events.filter(e => e.severity === "error");
          const warningEvents = events.filter(e => e.severity === "warning");

          // Create triage recommendations
          let triageText = `## Event Triage Report\n\n`;
          triageText += `**${events.length} events need attention**\n\n`;

          if (fatalEvents.length > 0) {
            triageText += `### 🔴 CRITICAL (${fatalEvents.length})\nThese are crashing your app for users!\n`;
            fatalEvents.forEach(e => {
              triageText += `- **${e.title}** - ${e.affected_users} users affected\n  \`${e.id}\`\n`;
            });
            triageText += "\n";
          }

          if (errorEvents.length > 0) {
            triageText += `### 🟠 HIGH PRIORITY (${errorEvents.length})\nThese are causing errors but not crashes.\n`;
            errorEvents.slice(0, 5).forEach(e => {
              triageText += `- **${e.title}** - ${e.occurrence_count} occurrences\n`;
            });
            triageText += "\n";
          }

          if (warningEvents.length > 0) {
            triageText += `### 🟡 MEDIUM PRIORITY (${warningEvents.length})\nWarnings that might become errors.\n`;
          }

          // Add risk context
          if (riskScores.length > 0) {
            const topRisk = riskScores[0];
            triageText += `\n### 🎯 Recommended Focus\nHighest risk area: **${topRisk.entity_identifier}** (Risk: ${topRisk.overall_score}/100)\n`;
          }

          triageText += `\n**Quick Actions:**\n`;
          triageText += `- Generate tests: \`argus_test_from_event(event_id, project_id)\`\n`;
          triageText += `- Batch generate: \`argus_batch_generate(project_id)\`\n`;

          return {
            content: [
              {
                type: "text" as const,
                text: triageText,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // SELF-HEALING - Configuration and pattern management
    // =========================================================================

    // Tool: argus_healing_config - Get/update self-healing configuration
    this.server.tool(
      "argus_healing_config",
      "View or update self-healing configuration. Control how Skopaq automatically fixes broken selectors, handles timeouts, and learns from patterns.",
      {
        organization_id: z.string().describe("The organization UUID"),
        project_id: z.string().optional().describe("Project-specific config (optional)"),
        action: z.enum(["get", "update"]).describe("Get or update configuration"),
        config: z.object({
          enabled: z.boolean().optional(),
          auto_apply: z.boolean().optional(),
          min_confidence_auto: z.number().optional(),
          heal_selectors: z.boolean().optional(),
          heal_timeouts: z.boolean().optional(),
          learn_from_success: z.boolean().optional(),
          notify_on_heal: z.boolean().optional(),
          require_approval: z.boolean().optional(),
        }).optional().describe("Configuration updates (for update action)"),
      },
      async ({ organization_id, project_id, action, config }) => {
        try {
          await this.requireAuth();
          if (action === "get") {
            const params = project_id ? `?project_id=${project_id}` : "";
            const result = await this.callBrainAPIWithAuth<HealingConfigResponse>(
              `/api/v1/healing/organizations/${organization_id}/config${params}`,
              "GET"
            );

            const statusEmoji = result.enabled ? "🟢 Enabled" : "🔴 Disabled";
            const autoApplyEmoji = result.auto_apply ? "✅ Auto" : "👤 Manual";

            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Self-Healing Configuration\n\n**Status:** ${statusEmoji}\n**Application:** ${autoApplyEmoji}\n\n### Settings:\n- Min confidence (auto): ${(result.min_confidence_auto * 100).toFixed(0)}%\n- Min confidence (suggest): ${(result.min_confidence_suggest * 100).toFixed(0)}%\n- Heal selectors: ${result.heal_selectors ? "Yes" : "No"}\n- Heal timeouts: ${result.heal_timeouts ? "Yes" : "No"}\n- Heal text content: ${result.heal_text_content ? "Yes" : "No"}\n- Learn from success: ${result.learn_from_success ? "Yes" : "No"}\n\n### Notifications:\n- Notify on heal: ${result.notify_on_heal ? "Yes" : "No"}\n- Require approval: ${result.require_approval ? "Yes" : "No"}`,
                },
              ],
            };
          }

          // Update config - Backend uses PUT method
          const result = await this.callBrainAPIWithAuth<HealingConfigResponse>(
            `/api/v1/healing/organizations/${organization_id}/config${project_id ? `?project_id=${project_id}` : ""}`,
            "PUT",
            config || {}
          );

          return {
            content: [
              {
                type: "text" as const,
                text: `## Configuration Updated ✅\n\nSelf-healing is now ${result.enabled ? "enabled" : "disabled"}.\n\nChanges will take effect immediately for new test runs.`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_healing_patterns - List learned healing patterns
    this.server.tool(
      "argus_healing_patterns",
      "View learned self-healing patterns. These are selector fixes that Skopaq has learned from past test runs and can apply automatically.",
      {
        organization_id: z.string().describe("The organization UUID"),
        project_id: z.string().optional().describe("Filter by project"),
        min_confidence: z.number().min(0).max(1).optional().describe("Minimum confidence filter (default: 0.5)"),
        limit: z.number().min(1).max(100).optional().describe("Max patterns (default: 20)"),
      },
      async ({ organization_id, project_id, min_confidence = 0.5, limit = 20 }) => {
        try {
          await this.requireAuth();
          const params = new URLSearchParams({
            min_confidence: min_confidence.toString(),
            limit: limit.toString(),
          });
          if (project_id) params.set("project_id", project_id);

          // Backend returns array directly, not wrapped
          const result = await this.callBrainAPIWithAuth<HealingPatternsResponse["patterns"]>(
            `/api/v1/healing/organizations/${organization_id}/patterns?${params}`,
            "GET"
          );

          // Handle both array response and wrapped response
          const patterns = Array.isArray(result) ? result : (result as unknown as { patterns: HealingPatternsResponse["patterns"] }).patterns || [];

          if (patterns.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Healing Patterns\n\nNo patterns learned yet. As tests run and selectors break, Skopaq will learn how to fix them automatically.\n\n**Tip:** Run tests with self-healing enabled to start building patterns.`,
                },
              ],
            };
          }

          const patternsList = patterns.map((p, i) => {
            const confidenceEmoji = p.confidence > 0.9 ? "🟢" : p.confidence > 0.7 ? "🟡" : "🔴";
            const successRate = p.success_count / (p.success_count + p.failure_count) * 100;
            return `${i + 1}. ${confidenceEmoji} **${p.error_type}** (${(p.confidence * 100).toFixed(0)}% confident)\n   From: \`${p.original_selector.slice(0, 40)}...\`\n   To: \`${p.healed_selector.slice(0, 40)}...\`\n   Success: ${successRate.toFixed(0)}% (${p.success_count}/${p.success_count + p.failure_count})`;
          }).join("\n\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Healing Patterns (${patterns.length} learned)\n\n${patternsList}\n\n**Legend:** 🟢 High confidence | 🟡 Medium | 🔴 Low`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_healing_stats - Get healing statistics
    this.server.tool(
      "argus_healing_stats",
      "Get comprehensive self-healing statistics. See how many tests have been healed, success rates, and trends over time.",
      {
        organization_id: z.string().describe("The organization UUID"),
        project_id: z.string().optional().describe("Filter by project"),
      },
      async ({ organization_id, project_id }) => {
        try {
          await this.requireAuth();
          const params = project_id ? `?project_id=${project_id}` : "";
          const result = await this.callBrainAPIWithAuth<HealingStatsResponse>(
            `/api/v1/healing/organizations/${organization_id}/stats${params}`,
            "GET"
          );

          const successEmoji = result.success_rate > 80 ? "🟢" : result.success_rate > 50 ? "🟡" : "🔴";

          let errorTypesText = "";
          if (Object.keys(result.top_error_types).length > 0) {
            errorTypesText = "\n### Top Error Types:\n" +
              Object.entries(result.top_error_types)
                .map(([type, count]) => `- ${type}: ${count}`)
                .join("\n");
          }

          let recentHealsText = "";
          if (result.recent_heals && result.recent_heals.length > 0) {
            recentHealsText = "\n### Recent Heals:\n" +
              result.recent_heals.slice(0, 5)
                .map(h => `- ${h.error_type}: \`${h.original.slice(0, 30)}...\` → \`${h.healed.slice(0, 30)}...\``)
                .join("\n");
          }

          return {
            content: [
              {
                type: "text" as const,
                text: `## Self-Healing Statistics\n\n### Overview:\n- **Total Patterns:** ${result.total_patterns}\n- **Total Heals Applied:** ${result.total_heals_applied}\n- **Success Rate:** ${successEmoji} ${result.success_rate.toFixed(1)}%\n- **Avg Confidence:** ${(result.avg_confidence * 100).toFixed(0)}%\n\n### Activity:\n- Last 24 hours: ${result.heals_last_24h} heals\n- Last 7 days: ${result.heals_last_7d} heals${errorTypesText}${recentHealsText}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_healing_review - Approve or reject healing suggestions
    this.server.tool(
      "argus_healing_review",
      "Review and approve/reject healing suggestions. When require_approval is enabled, heals wait for human review before being applied.",
      {
        organization_id: z.string().describe("The organization UUID"),
        pattern_id: z.string().describe("The pattern UUID to review"),
        action: z.enum(["approve", "reject"]).describe("Approve or reject the healing"),
      },
      async ({ organization_id, pattern_id, action }) => {
        try {
          const endpoint = action === "approve" ? "approve" : "reject";
          const result = await this.callBrainAPIWithAuth<{ success: boolean; message: string }>(
            `/api/v1/healing/organizations/${organization_id}/${endpoint}/${pattern_id}`,
            "POST",
            {}
          );

          const emoji = action === "approve" ? "✅" : "❌";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Healing ${action === "approve" ? "Approved" : "Rejected"} ${emoji}\n\n${result.message}\n\n${action === "approve" 
                  ? "This pattern will now be applied automatically in future test runs."
                  : "This pattern has been marked as unreliable and won't be used."}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // PROJECT MANAGEMENT - List and switch contexts
    // =========================================================================

    // Tool: argus_projects - List all projects
    this.server.tool(
      "argus_projects",
      "List all projects you have access to. Projects organize tests, events, and configurations for different applications.",
      {
        organization_id: z.string().optional().describe("Filter by organization (optional)"),
      },
      async ({ organization_id }) => {
        try {
          await this.requireAuth();
          const params = organization_id ? `?organization_id=${organization_id}` : "";
          // Backend returns array directly, not wrapped in { projects: [...] }
          const result = await this.callBrainAPIWithAuth<ProjectsResponse["projects"]>(
            `/api/v1/projects${params}`,
            "GET"
          );

          // Handle both array response and wrapped response
          const projects = Array.isArray(result) ? result : (result as unknown as ProjectsResponse).projects || [];

          if (projects.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Projects\n\nNo projects found. Create a project in the Skopaq dashboard to get started.\n\n**Tip:** Each project typically maps to one application or microservice.`,
                },
              ],
            };
          }

          const projectsList = projects.map((p, i) => {
            return `${i + 1}. **${p.name}**\n   ${p.description || "No description"}\n   URL: ${p.app_url || "Not set"}\n   Tests: ${p.test_count || 0} | Events: ${p.event_count || 0}\n   ID: \`${p.id}\``;
          }).join("\n\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Your Projects (${projects.length})\n\n${projectsList}\n\n**Tip:** Use the project ID with other commands like \`argus_events\`, \`argus_tests\`, etc.`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // TEST MANAGEMENT - List, review, and manage tests
    // =========================================================================

    // Tool: argus_tests - List tests with filters
    this.server.tool(
      "argus_tests",
      "List generated tests for a project. Filter by status to find tests pending review, approved tests, or rejected ones.",
      {
        project_id: z.string().describe("The project UUID"),
        status: z.enum(["pending", "approved", "rejected", "modified"]).optional().describe("Filter by review status"),
        limit: z.number().min(1).max(100).optional().describe("Max results (default: 20)"),
      },
      async ({ project_id, status, limit = 20 }) => {
        try {
          await this.requireAuth();
          const params = new URLSearchParams({ project_id, limit: limit.toString() });
          if (status) params.set("status", status);

          const result = await this.callBrainAPIWithAuth<GeneratedTestsResponse>(
            `/api/v1/quality/generated-tests?${params}`,
            "GET",
            
          );

          const tests = result.tests || [];

          if (tests.length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Generated Tests\n\nNo tests found${status ? ` with status "${status}"` : ""}.\n\n**Tip:** Use \`argus_test_from_event\` or \`argus_generate_test\` to create tests from production errors.`,
                },
              ],
            };
          }

          const pendingCount = tests.filter(t => t.status === "pending").length;
          const statusBanner = pendingCount > 0 
            ? `⚠️ **${pendingCount} tests need review!**\n\n`
            : "";

          const testsList = tests.map((t, i) => {
            const statusIcon = t.status === "approved" ? "✅" : t.status === "pending" ? "⏳" : t.status === "rejected" ? "❌" : "✏️";
            const confidenceEmoji = t.confidence_score > 0.8 ? "🟢" : t.confidence_score > 0.6 ? "🟡" : "🔴";
            return `${i + 1}. ${statusIcon} **${t.name}**\n   Confidence: ${confidenceEmoji} ${(t.confidence_score * 100).toFixed(0)}% | Framework: ${t.framework}\n   File: \`${t.test_file_path || "Not generated"}\`\n   ID: \`${t.id}\``;
          }).join("\n\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Generated Tests (${tests.length})\n\n${statusBanner}${testsList}\n\n**Actions:**\n- Review: \`argus_test_review(test_id, action)\`\n- Export: \`argus_export(test_id, language, framework)\``,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_test_review - Approve/reject/modify generated tests
    this.server.tool(
      "argus_test_review",
      "Review a generated test - approve it for use, reject it, or modify the code. Approved tests can be exported and run in CI.",
      {
        test_id: z.string().describe("The generated test UUID"),
        action: z.enum(["approve", "reject", "modify"]).describe("Review action"),
        review_notes: z.string().optional().describe("Notes about your review decision"),
        modified_code: z.string().optional().describe("Modified test code (for modify action)"),
      },
      async ({ test_id, action, review_notes, modified_code }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ success: boolean; message: string }>(
            "/api/v1/quality/update-test",
            "POST",
            {
              test_id,
              action,
              review_notes,
              modified_code,
            }
          );

          const emoji = action === "approve" ? "✅" : action === "reject" ? "❌" : "✏️";
          const actionText = action === "approve" ? "approved" : action === "reject" ? "rejected" : "modified";

          return {
            content: [
              {
                type: "text" as const,
                text: `## Test ${actionText.charAt(0).toUpperCase() + actionText.slice(1)} ${emoji}\n\n${result.message}\n\n${action === "approve" 
                  ? "**Next:** Export this test with `argus_export` to add it to your test suite."
                  : action === "modify"
                  ? "Your changes have been saved. Review again when ready to approve."
                  : "This test won't be used. Consider regenerating with more context."}`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // SMART INSIGHTS - AI-powered recommendations
    // =========================================================================

    // Tool: argus_what_to_test - AI recommendations on what to test
    this.server.tool(
      "argus_what_to_test",
      "Get AI-powered recommendations on what to test next. Analyzes risk scores, recent errors, and coverage gaps to prioritize testing efforts.",
      {
        project_id: z.string().describe("The project UUID"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          // Gather data for recommendations
          const [eventsResult, riskResult, statsResult] = await Promise.all([
            this.callBrainAPIWithAuth<ProductionEventsResponse>(
              `/api/v1/quality/events?project_id=${project_id}&status=new&limit=10`,
              "GET"
            ),
            this.callBrainAPIWithAuth<BrainRiskScoresResponse>(
              `/api/v1/quality/risk-scores?project_id=${project_id}&limit=5`,
              "GET"
            ),
            this.callBrainAPIWithAuth<BrainQualityStatsResponse>(
              `/api/v1/quality/stats?project_id=${project_id}`,
              "GET"
            ),
          ]);

          const events = eventsResult.events || [];
          const riskScores = riskResult.risk_scores || [];
          const stats = statsResult.stats;

          let recommendations = `## What to Test Next 🎯\n\n`;

          // Priority 1: High-risk areas without tests
          if (riskScores.length > 0) {
            const highRisk = riskScores.filter(r => r.overall_score > 70);
            if (highRisk.length > 0) {
              recommendations += `### 🔴 Critical Priority\nHigh-risk areas that need immediate test coverage:\n\n`;
              highRisk.forEach(r => {
                recommendations += `- **${r.entity_identifier}** (${r.entity_type})\n  Risk: ${r.overall_score}/100 | Errors: ${r.error_count} | Users: ${r.affected_users}\n`;
              });
              recommendations += "\n";
            }
          }

          // Priority 2: Recent production errors
          if (events.length > 0) {
            const fatalErrors = events.filter(e => e.severity === "fatal");
            const recentErrors = events.slice(0, 5);
            
            if (fatalErrors.length > 0) {
              recommendations += `### 🟠 Fatal Errors (${fatalErrors.length})\nThese are crashing your app:\n\n`;
              fatalErrors.forEach(e => {
                recommendations += `- **${e.title}**\n  ${e.affected_users} users affected | \`${e.id}\`\n`;
              });
              recommendations += "\n";
            } else if (recentErrors.length > 0) {
              recommendations += `### 🟡 Recent Errors (${recentErrors.length})\nNew errors that need test coverage:\n\n`;
              recentErrors.forEach(e => {
                recommendations += `- **${e.title}** (${e.severity})\n`;
              });
              recommendations += "\n";
            }
          }

          // Summary with action items
          recommendations += `### 📊 Coverage Summary\n`;
          recommendations += `- Total events: ${stats.total_events}\n`;
          recommendations += `- Tests generated: ${stats.total_generated_tests}\n`;
          recommendations += `- Coverage rate: ${stats.coverage_rate}%\n\n`;

          recommendations += `### 💡 Quick Actions\n`;
          if (events.length > 0) {
            recommendations += `- Generate tests for all new events: Use \`argus_batch_generate\`\n`;
          }
          if (stats.coverage_rate < 50) {
            recommendations += `- Low coverage! Focus on high-risk areas first\n`;
          }
          if (stats.tests_by_status && stats.tests_by_status["pending"] > 0) {
            recommendations += `- Review ${stats.tests_by_status["pending"]} pending tests with \`argus_tests\`\n`;
          }

          return {
            content: [
              {
                type: "text" as const,
                text: recommendations,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_coverage_gaps - Find untested areas
    this.server.tool(
      "argus_coverage_gaps",
      "Identify areas of your application that have production errors but no test coverage. These are your blind spots.",
      {
        project_id: z.string().describe("The project UUID"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const [eventsResult, testsResult] = await Promise.all([
            this.callBrainAPIWithAuth<ProductionEventsResponse>(
              `/api/v1/quality/events?project_id=${project_id}&limit=100`,
              "GET"
            ),
            this.callBrainAPIWithAuth<GeneratedTestsResponse>(
              `/api/v1/quality/generated-tests?project_id=${project_id}&status=approved&limit=100`,
              "GET"
            ),
          ]);

          const events = eventsResult.events || [];
          const tests = testsResult.tests || [];

          // Find components with errors but no tests
          const testedEventIds = new Set(tests.map(t => t.production_event_id).filter(Boolean));
          const untestedEvents = events.filter(e => !testedEventIds.has(e.id));

          // Group by component
          const componentGaps: Record<string, { errors: number; severity: string }> = {};
          untestedEvents.forEach(e => {
            const component = e.component || e.url || "Unknown";
            if (!componentGaps[component]) {
              componentGaps[component] = { errors: 0, severity: "warning" };
            }
            componentGaps[component].errors++;
            if (e.severity === "fatal" || (e.severity === "error" && componentGaps[component].severity === "warning")) {
              componentGaps[component].severity = e.severity;
            }
          });

          const coveragePercent = events.length > 0 
            ? ((events.length - untestedEvents.length) / events.length * 100).toFixed(1)
            : "100";

          if (Object.keys(componentGaps).length === 0) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: `## Coverage Gaps\n\n✅ **No gaps found!** All known production errors have test coverage.\n\nCoverage: ${coveragePercent}%`,
                },
              ],
            };
          }

          const gapsList = Object.entries(componentGaps)
            .sort((a, b) => b[1].errors - a[1].errors)
            .map(([component, data], i) => {
              const icon = data.severity === "fatal" ? "🔴" : data.severity === "error" ? "🟠" : "🟡";
              return `${i + 1}. ${icon} **${component}**\n   ${data.errors} untested error${data.errors > 1 ? "s" : ""} (${data.severity})`;
            })
            .join("\n\n");

          return {
            content: [
              {
                type: "text" as const,
                text: `## Coverage Gaps Found! ⚠️\n\n**Coverage:** ${coveragePercent}% (${events.length - untestedEvents.length}/${events.length} events)\n\n### Untested Areas:\n\n${gapsList}\n\n**Action:** Generate tests with \`argus_test_from_event\` for critical gaps.`,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_batch_generate - Generate tests for multiple events
    this.server.tool(
      "argus_batch_generate",
      "Generate tests for multiple production events at once. Perfect for catching up on test coverage after connecting a new error source.",
      {
        project_id: z.string().describe("The project UUID"),
        status: z.enum(["new", "analyzing"]).optional().describe("Process events with this status (default: new)"),
        limit: z.number().min(1).max(50).optional().describe("Max events to process (default: 10)"),
        framework: z.enum(["playwright", "cypress", "jest"]).optional().describe("Test framework (default: playwright)"),
      },
      async ({ project_id, status = "new", limit = 10, framework = "playwright" }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{
            success: boolean;
            message: string;
            job_id: string;
            results: Array<{
              event_id: string;
              success: boolean;
              test_id?: string;
              error?: string;
            }>;
          }>(
            "/api/v1/quality/batch-generate",
            "POST",
            {
              project_id,
              status,
              limit,
              framework,
            }
          );

          const successCount = result.results.filter(r => r.success).length;
          const failCount = result.results.filter(r => !r.success).length;

          let resultText = `## Batch Generation Complete\n\n`;
          resultText += `**Generated:** ${successCount}/${result.results.length} tests\n`;
          resultText += `**Framework:** ${framework}\n`;
          resultText += `**Job ID:** \`${result.job_id}\`\n\n`;

          if (successCount > 0) {
            resultText += `### ✅ Successful (${successCount})\n`;
            result.results.filter(r => r.success).slice(0, 5).forEach(r => {
              resultText += `- Event \`${r.event_id.slice(0, 8)}...\` → Test \`${r.test_id?.slice(0, 8)}...\`\n`;
            });
            if (successCount > 5) resultText += `- ... and ${successCount - 5} more\n`;
            resultText += "\n";
          }

          if (failCount > 0) {
            resultText += `### ❌ Failed (${failCount})\n`;
            result.results.filter(r => !r.success).slice(0, 3).forEach(r => {
              resultText += `- Event \`${r.event_id.slice(0, 8)}...\`: ${r.error}\n`;
            });
            resultText += "\n";
          }

          resultText += `**Next:** Review generated tests with \`argus_tests(project_id, status="pending")\``;

          return {
            content: [
              {
                type: "text" as const,
                text: resultText,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_ask - Conversational AI for testing questions (routes to backend AI chat)
    this.server.tool(
      "argus_ask",
      "Ask any question about your tests, errors, or testing strategy. The AI will analyze your data and provide insights using the full Skopaq AI backend with multi-provider routing, Cognee semantic search, and conversation memory.",
      {
        question: z.string().describe("Your question about testing"),
        project_id: z.string().optional().describe("Project context (optional)"),
        thread_id: z.string().optional().describe("Conversation thread ID for multi-turn chat (optional)"),
      },
      async ({ question, project_id, thread_id }) => {
        try {
          await this.requireAuth();

          // Build context-enriched message
          let enrichedQuestion = question;
          if (project_id) {
            enrichedQuestion = `[Project context: ${project_id}] ${question}`;
          }

          // Route to backend AI chat endpoint
          const chatResponse = await this.callBrainAPIWithAuth<{
            message: string;
            thread_id: string;
            tool_calls?: Array<{ name: string; args: Record<string, unknown>; result?: string }>;
          }>(
            `/api/v1/chat/message`,
            "POST",
            {
              messages: [{ role: "user", content: enrichedQuestion }],
              thread_id: thread_id || undefined,
              app_url: project_id ? undefined : undefined,
            }
          );

          let answer = chatResponse.message || "No response received.";

          // Append tool call info if AI used tools
          if (chatResponse.tool_calls && chatResponse.tool_calls.length > 0) {
            answer += `\n\n---\n*AI used ${chatResponse.tool_calls.length} tool(s): ${chatResponse.tool_calls.map(tc => tc.name).join(", ")}*`;
          }

          // Append thread ID for follow-up conversations
          if (chatResponse.thread_id) {
            answer += `\n\n*Thread: \`${chatResponse.thread_id}\` — use this thread_id for follow-up questions*`;
          }

          return {
            content: [
              {
                type: "text" as const,
                text: answer,
              },
            ],
          };
        } catch (error) {
          const message = error instanceof Error ? error.message : "Unknown error";
          if (message === "AUTH_REQUIRED") {
            return this.handleError(error);
          }
          return {
            content: [
              {
                type: "text" as const,
                text: `## Error Processing Question\n\n${message}\n\n**Tip:** If this is an AI configuration issue, ensure your AI provider keys are set in Settings → AI Configuration.`,
              },
            ],
            isError: true,
          };
        }
      }
    );

    // Tool: argus_dashboard - Get a quick overview of everything
    this.server.tool(
      "argus_dashboard",
      "Get a comprehensive dashboard view of your testing status. Shows quality score, recent events, pending tests, and actionable insights all in one place.",
      {
        project_id: z.string().describe("The project UUID"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          // Fetch all relevant data in parallel
          const [scoreResult, statsResult, eventsResult, testsResult, riskResult] = await Promise.all([
            this.callBrainAPIWithAuth<BrainQualityScoreResponse>(
              `/api/v1/quality/score?project_id=${project_id}`,
              "GET"
            ),
            this.callBrainAPIWithAuth<BrainQualityStatsResponse>(
              `/api/v1/quality/stats?project_id=${project_id}`,
              "GET"
            ),
            this.callBrainAPIWithAuth<ProductionEventsResponse>(
              `/api/v1/quality/events?project_id=${project_id}&limit=5`,
              "GET"
            ),
            this.callBrainAPIWithAuth<GeneratedTestsResponse>(
              `/api/v1/quality/generated-tests?project_id=${project_id}&status=pending&limit=5`,
              "GET"
            ),
            this.callBrainAPIWithAuth<BrainRiskScoresResponse>(
              `/api/v1/quality/risk-scores?project_id=${project_id}&limit=3`,
              "GET"
            ),
          ]);

          const stats = statsResult.stats;
          const events = eventsResult.events || [];
          const tests = testsResult.tests || [];
          const risks = riskResult.risk_scores || [];

          // Build dashboard
          const scoreEmoji = scoreResult.quality_score >= 80 ? "🟢" : scoreResult.quality_score >= 50 ? "🟡" : "🔴";
          const riskEmoji = scoreResult.risk_level === "low" ? "🟢" : scoreResult.risk_level === "medium" ? "🟡" : "🔴";

          let dashboard = `# Skopaq Dashboard 📊\n\n`;
          
          // Quality Score Section
          dashboard += `## Quality Score: ${scoreEmoji} ${scoreResult.quality_score}/100\n\n`;
          dashboard += `| Metric | Value |\n|--------|-------|\n`;
          dashboard += `| Risk Level | ${riskEmoji} ${scoreResult.risk_level.toUpperCase()} |\n`;
          dashboard += `| Test Coverage | ${scoreResult.test_coverage}% |\n`;
          dashboard += `| Production Events | ${scoreResult.total_events} |\n`;
          dashboard += `| Generated Tests | ${scoreResult.total_tests} |\n`;
          dashboard += `| Approved Tests | ${scoreResult.approved_tests} |\n\n`;

          // Alerts Section
          const newEvents = events.filter(e => e.status === "new").length;
          const pendingTests = tests.length;
          
          if (newEvents > 0 || pendingTests > 0) {
            dashboard += `## ⚠️ Needs Attention\n\n`;
            if (newEvents > 0) {
              dashboard += `- **${newEvents} new production errors** need tests\n`;
            }
            if (pendingTests > 0) {
              dashboard += `- **${pendingTests} tests pending review**\n`;
            }
            dashboard += "\n";
          }

          // High Risk Areas
          if (risks.length > 0) {
            dashboard += `## 🎯 High Risk Areas\n\n`;
            risks.forEach(r => {
              const emoji = r.overall_score > 70 ? "🔴" : r.overall_score > 40 ? "🟡" : "🟢";
              dashboard += `- ${emoji} **${r.entity_identifier}**: ${r.overall_score}/100 risk\n`;
            });
            dashboard += "\n";
          }

          // Recent Events
          if (events.length > 0) {
            dashboard += `## 📋 Recent Events\n\n`;
            events.slice(0, 3).forEach(e => {
              const icon = e.severity === "fatal" ? "🔴" : e.severity === "error" ? "🟠" : "🟡";
              dashboard += `- ${icon} ${e.title}\n`;
            });
            dashboard += "\n";
          }

          // Quick Actions
          dashboard += `## ⚡ Quick Actions\n\n`;
          dashboard += `\`\`\`\n`;
          dashboard += `argus_events("${project_id}")           # View all events\n`;
          dashboard += `argus_what_to_test("${project_id}")     # Get recommendations\n`;
          dashboard += `argus_batch_generate("${project_id}")   # Generate tests\n`;
          dashboard += `argus_tests("${project_id}")            # Review tests\n`;
          dashboard += `\`\`\``;

          return {
            content: [
              {
                type: "text" as const,
                text: dashboard,
              },
            ],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );


    // =====================================================
    // CI/CD INTEGRATION TOOLS (RAP-276)
    // =====================================================

    // Tool: argus_cicd_test_impact - Analyze which tests are affected by code changes
    this.server.tool(
      "argus_cicd_test_impact",
      "Analyze which tests are affected by code changes in a commit. Uses AI to determine test impact based on changed files, dependencies, and historical patterns. Returns prioritized list of tests to run.",
      {
        project_id: z.string().describe("The project UUID"),
        commit_sha: z.string().describe("Git commit SHA to analyze"),
        branch: z.string().optional().default("main").describe("Git branch name"),
        changed_files: z.array(z.object({
          path: z.string().describe("File path"),
          change_type: z.enum(["added", "modified", "deleted", "renamed"]).optional().default("modified").describe("Type of change"),
          additions: z.number().optional().default(0).describe("Lines added"),
          deletions: z.number().optional().default(0).describe("Lines deleted"),
        })).describe("Array of changed files in the commit"),
      },
      async ({ project_id, commit_sha, branch, changed_files }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<CICDTestImpactResponse>(
            "/api/v1/cicd/test-impact/analyze",
            "POST",
            {
              project_id,
              commit_sha,
              branch,
              changed_files,
            }
          );

          const confidenceEmoji = result.confidence_score > 0.8 ? "🟢" : result.confidence_score > 0.5 ? "🟡" : "🔴";

          let output = `# Test Impact Analysis\n\n`;
          output += `**Commit**: \`${result.commit_sha.substring(0, 7)}\` on \`${result.branch}\`\n`;
          output += `**Confidence**: ${confidenceEmoji} ${(result.confidence_score * 100).toFixed(0)}%\n`;
          output += `**Analysis Time**: ${result.analysis_time_ms}ms\n\n`;

          output += `## Summary\n\n`;
          output += `| Metric | Value |\n|--------|-------|\n`;
          output += `| Files Changed | ${result.total_files_changed} |\n`;
          output += `| Tests Impacted | ${result.total_tests_impacted} |\n`;
          output += `| Recommended to Run | ${result.recommended_tests.length} |\n`;
          output += `| Safe to Skip | ${result.skip_candidates.length} |\n\n`;

          if (result.changed_files && result.changed_files.length > 0) {
            output += `## Changed Files\n\n`;
            output += `| File | Type | +/- |\n|------|------|-----|\n`;
            result.changed_files.slice(0, 10).forEach((file) => {
              output += `| \`${file.path}\` | ${file.change_type} | +${file.additions}/-${file.deletions} |\n`;
            });
            if (result.changed_files.length > 10) {
              output += `\n_...and ${result.changed_files.length - 10} more files_\n`;
            }
            output += `\n`;
          }

          if (result.impacted_tests && result.impacted_tests.length > 0) {
            output += `## Impacted Tests\n\n`;
            output += `| Test | Impact | Priority | Reason |\n|------|--------|----------|--------|\n`;
            result.impacted_tests.slice(0, 15).forEach((test) => {
              const impactEmoji = test.impact_score > 0.7 ? "🔴" : test.impact_score > 0.4 ? "🟡" : "🟢";
              output += `| ${test.test_name} | ${impactEmoji} ${(test.impact_score * 100).toFixed(0)}% | ${test.priority} | ${test.reason} |\n`;
            });
            if (result.impacted_tests.length > 15) {
              output += `\n_...and ${result.impacted_tests.length - 15} more tests_\n`;
            }
            output += `\n`;
          }

          if (result.recommended_tests && result.recommended_tests.length > 0) {
            output += `## Recommended Test Order\n\n`;
            output += `Run these tests first (highest impact):\n`;
            result.recommended_tests.slice(0, 10).forEach((testId, i) => {
              output += `${i + 1}. \`${testId}\`\n`;
            });
            output += `\n`;
          }

          if (result.skip_candidates && result.skip_candidates.length > 0) {
            output += `## Safe to Skip\n\n`;
            output += `These tests are unlikely to be affected:\n`;
            result.skip_candidates.slice(0, 5).forEach((testId) => {
              output += `- \`${testId}\`\n`;
            });
            if (result.skip_candidates.length > 5) {
              output += `\n_...and ${result.skip_candidates.length - 5} more_\n`;
            }
          }

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_cicd_deployment_risk - Get deployment risk assessment
    this.server.tool(
      "argus_cicd_deployment_risk",
      "Calculate deployment risk score for a project or specific commit. Analyzes CI/CD failure rates, test coverage, code complexity, and historical patterns to assess deployment safety.",
      {
        project_id: z.string().describe("The project UUID"),
        commit_sha: z.string().optional().describe("Specific commit SHA to assess (optional)"),
        branch: z.string().optional().describe("Git branch name (optional)"),
      },
      async ({ project_id, commit_sha, branch }) => {
        try {
          await this.requireAuth();

          const params = new URLSearchParams({ project_id });
          if (commit_sha) params.set("commit_sha", commit_sha);
          if (branch) params.set("branch", branch);

          const result = await this.callBrainAPIWithAuth<CICDDeploymentRiskResponse>(
            `/api/v1/cicd/deployment-risk?${params}`,
            "GET"
          );

          const riskEmoji = result.risk_level === "critical" ? "🔴" : result.risk_level === "high" ? "🟠" : result.risk_level === "medium" ? "🟡" : "🟢";
          const riskBar = "█".repeat(Math.floor(result.risk_score / 10)) + "░".repeat(10 - Math.floor(result.risk_score / 10));

          let output = `# Deployment Risk Assessment\n\n`;
          output += `## Risk Score: ${riskEmoji} ${result.risk_score}/100\n\n`;
          output += `\`[${riskBar}]\` **${result.risk_level.toUpperCase()}**\n\n`;

          if (result.commit_sha) {
            output += `**Commit**: \`${result.commit_sha.substring(0, 7)}\`\n`;
          }
          output += `**Project**: ${result.project_id}\n\n`;

          output += `## Risk Factors\n\n`;
          output += `| Factor | Value |\n|--------|-------|\n`;
          for (const [key, value] of Object.entries(result.factors)) {
            const displayKey = key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
            const displayValue = value === null ? "N/A" : typeof value === "number" ? `${value.toFixed(1)}%` : String(value);
            output += `| ${displayKey} | ${displayValue} |\n`;
          }
          output += `\n`;

          output += `## Test Recommendations\n\n`;
          output += `- **Tests to Run**: ${result.tests_to_run}\n`;
          output += `- **Safe to Skip**: ${result.skip_candidates}\n\n`;

          if (result.recommendations && result.recommendations.length > 0) {
            output += `## Recommendations\n\n`;
            result.recommendations.forEach((rec, i) => {
              output += `${i + 1}. ${rec}\n`;
            });
            output += `\n`;
          }

          // Add deployment guidance based on risk level
          output += `## Deployment Guidance\n\n`;
          if (result.risk_level === "low") {
            output += `✅ **Safe to Deploy** - Low risk detected. Proceed with standard deployment process.\n`;
          } else if (result.risk_level === "medium") {
            output += `⚠️ **Deploy with Caution** - Medium risk detected. Consider running recommended tests before deployment.\n`;
          } else if (result.risk_level === "high") {
            output += `🟠 **Review Required** - High risk detected. Run all impacted tests and get approval before deploying.\n`;
          } else {
            output += `🔴 **Deployment Not Recommended** - Critical risk detected. Address issues before attempting deployment.\n`;
          }

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_cicd_builds - List build history
    this.server.tool(
      "argus_cicd_builds",
      "List CI/CD build history for a project. Shows build status, test results, coverage, and timing information.",
      {
        project_id: z.string().describe("The project UUID"),
        limit: z.number().optional().default(20).describe("Maximum number of builds to return (default: 20)"),
        status: z.enum(["pending", "running", "success", "failed", "cancelled", "skipped"]).optional().describe("Filter by build status"),
      },
      async ({ project_id, limit, status }) => {
        try {
          await this.requireAuth();

          const params = new URLSearchParams({
            project_id,
            limit: limit.toString(),
          });
          if (status) params.set("status", status);

          const result = await this.callBrainAPIWithAuth<CICDBuildsResponse>(
            `/api/v1/cicd/builds?${params}`,
            "GET"
          );

          if (!result.builds || result.builds.length === 0) {
            return {
              content: [{
                type: "text" as const,
                text: `# CI/CD Builds\n\nNo builds found for this project.${status ? ` (filtered by status: ${status})` : ""}`,
              }],
            };
          }

          let output = `# CI/CD Builds\n\n`;
          output += `**Total**: ${result.total} builds${status ? ` (showing ${status} only)` : ""}\n\n`;

          // Calculate stats
          const successCount = result.builds.filter((b) => b.status === "success").length;
          const failedCount = result.builds.filter((b) => b.status === "failed").length;
          const successRate = result.builds.length > 0 ? ((successCount / result.builds.length) * 100).toFixed(0) : "0";

          output += `## Quick Stats\n\n`;
          output += `| Metric | Value |\n|--------|-------|\n`;
          output += `| Success Rate | ${successRate}% |\n`;
          output += `| Passed | ${successCount} |\n`;
          output += `| Failed | ${failedCount} |\n\n`;

          output += `## Recent Builds\n\n`;
          output += `| # | Branch | Status | Tests | Coverage | Duration |\n`;
          output += `|---|--------|--------|-------|----------|----------|\n`;

          result.builds.slice(0, limit).forEach((build) => {
            const statusEmoji = build.status === "success" ? "✅" : build.status === "failed" ? "❌" : build.status === "running" ? "🔄" : "⏸️";
            const tests = `${build.tests_passed}/${build.tests_total}`;
            const coverage = build.coverage_percent !== null && build.coverage_percent !== undefined ? `${build.coverage_percent.toFixed(0)}%` : "-";
            const duration = build.duration_ms ? `${(build.duration_ms / 1000).toFixed(0)}s` : "-";
            const branchShort = build.branch.length > 20 ? build.branch.substring(0, 17) + "..." : build.branch;
            output += `| ${build.build_number} | \`${branchShort}\` | ${statusEmoji} ${build.status} | ${tests} | ${coverage} | ${duration} |\n`;
          });

          output += `\n`;

          // Show last failed build details if any
          const lastFailed = result.builds.find((b) => b.status === "failed");
          if (lastFailed) {
            output += `## Last Failed Build (#${lastFailed.build_number})\n\n`;
            output += `- **Branch**: \`${lastFailed.branch}\`\n`;
            output += `- **Commit**: \`${lastFailed.commit_sha.substring(0, 7)}\`\n`;
            if (lastFailed.commit_message) {
              output += `- **Message**: ${lastFailed.commit_message.substring(0, 80)}${lastFailed.commit_message.length > 80 ? "..." : ""}\n`;
            }
            output += `- **Tests Failed**: ${lastFailed.tests_failed}\n`;
            if (lastFailed.logs_url) {
              output += `- **Logs**: ${lastFailed.logs_url}\n`;
            }
          }

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_cicd_pipelines - View CI/CD pipeline status
    this.server.tool(
      "argus_cicd_pipelines",
      "View CI/CD pipeline status and history. Shows workflow runs, stages, and their outcomes from GitHub Actions or other CI providers.",
      {
        project_id: z.string().describe("The project UUID"),
        limit: z.number().optional().default(20).describe("Maximum number of pipelines to return (default: 20)"),
        status: z.enum(["queued", "in_progress", "completed", "cancelled"]).optional().describe("Filter by pipeline status"),
      },
      async ({ project_id, limit, status }) => {
        try {
          await this.requireAuth();

          const params = new URLSearchParams({
            project_id,
            limit: limit.toString(),
          });
          if (status) params.set("status", status);

          const result = await this.callBrainAPIWithAuth<CICDPipelinesResponse>(
            `/api/v1/cicd/pipelines?${params}`,
            "GET"
          );

          if (!result.pipelines || result.pipelines.length === 0) {
            return {
              content: [{
                type: "text" as const,
                text: `# CI/CD Pipelines\n\nNo pipelines found for this project.${status ? ` (filtered by status: ${status})` : ""}`,
              }],
            };
          }

          let output = `# CI/CD Pipelines\n\n`;
          output += `**Total**: ${result.total} pipelines${status ? ` (showing ${status} only)` : ""}\n\n`;

          // Calculate stats
          const successCount = result.pipelines.filter((p) => p.conclusion === "success").length;
          const failedCount = result.pipelines.filter((p) => p.conclusion === "failure").length;
          const inProgress = result.pipelines.filter((p) => p.status === "in_progress").length;

          output += `## Status Overview\n\n`;
          output += `| Status | Count |\n|--------|-------|\n`;
          output += `| ✅ Success | ${successCount} |\n`;
          output += `| ❌ Failed | ${failedCount} |\n`;
          output += `| 🔄 In Progress | ${inProgress} |\n\n`;

          output += `## Recent Pipelines\n\n`;

          result.pipelines.slice(0, limit).forEach((pipeline, i) => {
            const statusEmoji = pipeline.status === "completed"
              ? (pipeline.conclusion === "success" ? "✅" : pipeline.conclusion === "failure" ? "❌" : "⏹️")
              : pipeline.status === "in_progress" ? "🔄" : "⏸️";

            output += `### ${i + 1}. ${statusEmoji} ${pipeline.workflow_name || "Pipeline"} #${pipeline.run_number || pipeline.id.substring(0, 8)}\n\n`;
            output += `- **Status**: ${pipeline.status}${pipeline.conclusion ? ` (${pipeline.conclusion})` : ""}\n`;
            if (pipeline.branch) output += `- **Branch**: \`${pipeline.branch}\`\n`;
            if (pipeline.commit_sha) output += `- **Commit**: \`${pipeline.commit_sha.substring(0, 7)}\`\n`;
            if (pipeline.actor) output += `- **Triggered by**: ${pipeline.actor}\n`;
            if (pipeline.event) output += `- **Event**: ${pipeline.event}\n`;
            if (pipeline.html_url) output += `- **URL**: ${pipeline.html_url}\n`;

            if (pipeline.stages && pipeline.stages.length > 0) {
              output += `- **Stages**:\n`;
              pipeline.stages.forEach((stage) => {
                const stageEmoji = stage.status === "success" ? "✅" : stage.status === "failure" ? "❌" : stage.status === "running" ? "🔄" : "⏸️";
                const duration = stage.duration_seconds ? ` (${stage.duration_seconds}s)` : "";
                output += `  - ${stageEmoji} ${stage.name}${duration}\n`;
              });
            }

            output += `\n`;
          });

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =====================================================
    // CORRELATION & ANALYTICS TOOLS (RAP-281)
    // =====================================================

    // Tool: argus_correlations_timeline - Get unified SDLC event timeline
    this.server.tool(
      "argus_correlations_timeline",
      "View unified timeline of SDLC events across all integrations. Shows commits, PRs, deployments, errors, and incidents in chronological order. Enables cross-platform correlation analysis.",
      {
        project_id: z.string().describe("The project UUID"),
        days: z.number().optional().default(7).describe("Number of days to look back (1-90, default: 7)"),
        event_types: z.array(z.string()).optional().describe("Filter by event types (e.g., ['commit', 'deploy', 'error', 'incident'])"),
        limit: z.number().optional().default(50).describe("Maximum events to return (default: 50)"),
      },
      async ({ project_id, days, event_types, limit }) => {
        try {
          await this.requireAuth();

          const params = new URLSearchParams({
            project_id,
            days: (days || 7).toString(),
            limit: (limit || 50).toString(),
          });
          if (event_types && event_types.length > 0) {
            event_types.forEach(t => params.append("event_types", t));
          }

          const result = await this.callBrainAPIWithAuth<{
            events: Array<{
              id: string;
              event_type: string;
              source_platform: string;
              external_id: string;
              external_url?: string;
              title?: string;
              occurred_at: string;
              commit_sha?: string;
              pr_number?: number;
              jira_key?: string;
              deploy_id?: string;
              data: Record<string, unknown>;
            }>;
            total_count: number;
          }>(
            `/api/v1/correlations/timeline?${params}`,
            "GET"
          );

          if (!result.events || result.events.length === 0) {
            return {
              content: [{
                type: "text" as const,
                text: `## SDLC Timeline\n\nNo events found for the last ${days} day(s).\n\n**Tip:** Connect integrations (GitHub, Sentry, Jira) to see events in the timeline.`,
              }],
            };
          }

          let output = `# SDLC Event Timeline\n\n`;
          output += `**Period:** Last ${days} day(s)\n`;
          output += `**Total Events:** ${result.total_count}\n`;
          if (event_types && event_types.length > 0) {
            output += `**Filtered by:** ${event_types.join(", ")}\n`;
          }
          output += `\n---\n\n`;

          // Group events by date
          const eventsByDate: Record<string, typeof result.events> = {};
          result.events.forEach((event) => {
            const date = new Date(event.occurred_at).toISOString().split("T")[0];
            if (!eventsByDate[date]) {
              eventsByDate[date] = [];
            }
            eventsByDate[date].push(event);
          });

          for (const [date, events] of Object.entries(eventsByDate)) {
            output += `## ${date}\n\n`;

            events.forEach((event) => {
              const typeEmoji = {
                commit: "📝",
                pr: "🔀",
                deploy: "🚀",
                error: "❌",
                incident: "🚨",
                test_run: "🧪",
                build: "🔨",
                requirement: "📋",
              }[event.event_type] || "📌";

              const time = new Date(event.occurred_at).toLocaleTimeString("en-US", {
                hour: "2-digit",
                minute: "2-digit",
              });

              output += `**${time}** ${typeEmoji} **${event.event_type.toUpperCase()}** - ${event.title || event.external_id}\n`;
              output += `- Source: ${event.source_platform}\n`;
              if (event.commit_sha) output += `- Commit: \`${event.commit_sha.substring(0, 7)}\`\n`;
              if (event.pr_number) output += `- PR: #${event.pr_number}\n`;
              if (event.jira_key) output += `- Jira: ${event.jira_key}\n`;
              if (event.external_url) output += `- [View](${event.external_url})\n`;
              output += `\n`;
            });
          }

          output += `---\n`;
          output += `**Tip:** Use \`argus_correlations_root_cause\` with an event ID to trace its root cause.\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_correlations_root_cause - AI root cause analysis
    this.server.tool(
      "argus_correlations_root_cause",
      "Perform AI-powered root cause analysis for an error or incident. Traces back through the event timeline to find commits, deployments, or other changes that may have caused the issue.",
      {
        event_id: z.string().describe("The event ID to analyze (typically an error or incident)"),
        hours_before: z.number().optional().default(48).describe("Hours to look back for potential causes (default: 48)"),
      },
      async ({ event_id, hours_before }) => {
        try {
          await this.requireAuth();

          const params = new URLSearchParams({
            hours_before: (hours_before || 48).toString(),
          });

          const result = await this.callBrainAPIWithAuth<{
            target_event: {
              id: string;
              event_type: string;
              source_platform: string;
              title?: string;
              occurred_at: string;
            };
            root_cause_chain: Array<{
              event: {
                id: string;
                event_type: string;
                title?: string;
                occurred_at: string;
                external_url?: string;
              };
              correlation_type?: string;
              confidence: number;
            }>;
            likely_root_cause?: {
              id: string;
              event_type: string;
              title?: string;
              occurred_at: string;
              external_url?: string;
            };
            confidence: number;
            analysis_summary: string;
          }>(
            `/api/v1/correlations/root-cause/${event_id}?${params}`,
            "GET"
          );

          const confidenceEmoji = result.confidence > 0.7 ? "🟢" : result.confidence > 0.4 ? "🟡" : "🔴";

          let output = `# Root Cause Analysis\n\n`;
          output += `## Target Event\n\n`;
          output += `- **Type:** ${result.target_event.event_type}\n`;
          output += `- **Title:** ${result.target_event.title || "N/A"}\n`;
          output += `- **Occurred:** ${result.target_event.occurred_at}\n`;
          output += `- **Source:** ${result.target_event.source_platform}\n\n`;

          output += `## Analysis\n\n`;
          output += `${result.analysis_summary}\n\n`;
          output += `**Confidence:** ${confidenceEmoji} ${(result.confidence * 100).toFixed(0)}%\n\n`;

          if (result.likely_root_cause) {
            output += `## Likely Root Cause\n\n`;
            const rc = result.likely_root_cause;
            output += `- **Type:** ${rc.event_type}\n`;
            output += `- **Title:** ${rc.title || "N/A"}\n`;
            output += `- **Occurred:** ${rc.occurred_at}\n`;
            if (rc.external_url) {
              output += `- [View Details](${rc.external_url})\n`;
            }
            output += `\n`;
          }

          if (result.root_cause_chain.length > 0) {
            output += `## Event Chain (${result.root_cause_chain.length} related events)\n\n`;
            output += `| # | Type | Title | Time | Confidence |\n`;
            output += `|---|------|-------|------|------------|\n`;

            result.root_cause_chain.forEach((item, i) => {
              const confEmoji = item.confidence > 0.7 ? "🟢" : item.confidence > 0.4 ? "🟡" : "⚪";
              const title = item.event.title || item.event.id.substring(0, 8);
              output += `| ${i + 1} | ${item.event.event_type} | ${title} | ${new Date(item.event.occurred_at).toLocaleString()} | ${confEmoji} ${(item.confidence * 100).toFixed(0)}% |\n`;
            });
            output += `\n`;
          }

          output += `---\n`;
          output += `**Actions:**\n`;
          output += `- Use \`argus_correlations_insights\` to get AI-powered recommendations\n`;
          output += `- Use \`argus_correlations_timeline\` to see the full event context\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_correlations_insights - Get AI-powered insights
    this.server.tool(
      "argus_correlations_insights",
      "Get AI-generated insights from SDLC correlation analysis. Identifies patterns, risks, and recommendations based on commits, deployments, errors, and incidents.",
      {
        project_id: z.string().describe("The project UUID"),
        limit: z.number().optional().default(10).describe("Maximum insights to return (default: 10)"),
        status: z.enum(["active", "acknowledged", "resolved", "dismissed"]).optional().default("active").describe("Filter by insight status"),
      },
      async ({ project_id, limit, status }) => {
        try {
          await this.requireAuth();

          const params = new URLSearchParams({
            project_id,
            limit: (limit || 10).toString(),
            status: status || "active",
          });

          const result = await this.callBrainAPIWithAuth<Array<{
            id: string;
            insight_type: string;
            severity: string;
            title: string;
            description: string;
            recommendations: Array<{ action: string; priority: string }>;
            event_ids: string[];
            status: string;
            created_at: string;
          }>>(
            `/api/v1/correlations/insights?${params}`,
            "GET"
          );

          if (!result || result.length === 0) {
            return {
              content: [{
                type: "text" as const,
                text: `## AI Insights\n\nNo ${status} insights found for this project.\n\n**Tip:** Insights are generated automatically when patterns are detected in SDLC events. Connect more integrations to enable richer analysis.`,
              }],
            };
          }

          let output = `# AI-Powered Insights\n\n`;
          output += `**Project:** ${project_id}\n`;
          output += `**Showing:** ${result.length} ${status} insight(s)\n\n`;

          result.forEach((insight, i) => {
            const severityEmoji = {
              critical: "🔴",
              high: "🟠",
              medium: "🟡",
              low: "🟢",
              info: "ℹ️",
            }[insight.severity] || "⚪";

            const typeEmoji = {
              failure_cluster: "🔥",
              deployment_risk: "🚀",
              performance_trend: "📈",
              coverage_gap: "🕳️",
              recommendation: "💡",
            }[insight.insight_type] || "📊";

            output += `## ${i + 1}. ${typeEmoji} ${insight.title}\n\n`;
            output += `**Severity:** ${severityEmoji} ${insight.severity.toUpperCase()}\n`;
            output += `**Type:** ${insight.insight_type.replace(/_/g, " ")}\n`;
            output += `**Created:** ${new Date(insight.created_at).toLocaleString()}\n\n`;
            output += `${insight.description}\n\n`;

            if (insight.recommendations && insight.recommendations.length > 0) {
              output += `**Recommendations:**\n`;
              insight.recommendations.forEach((rec, j) => {
                output += `${j + 1}. ${rec.action} (${rec.priority} priority)\n`;
              });
              output += `\n`;
            }

            if (insight.event_ids && insight.event_ids.length > 0) {
              output += `**Related Events:** ${insight.event_ids.length} event(s)\n`;
            }

            output += `**ID:** \`${insight.id}\`\n\n`;
            output += `---\n\n`;
          });

          output += `**Actions:**\n`;
          output += `- Use \`argus_correlations_root_cause\` to analyze specific events\n`;
          output += `- Acknowledge/resolve insights via the dashboard\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_correlations_query - Natural language query for correlations
    this.server.tool(
      "argus_correlations_query",
      "Query correlation data using natural language. Ask questions like 'What deployments caused errors last week?' or 'Show PRs without tests that failed in production'.",
      {
        project_id: z.string().describe("The project UUID"),
        query: z.string().describe("Natural language query (e.g., 'What caused the outage on Monday?')"),
      },
      async ({ project_id, query }) => {
        try {
          await this.requireAuth();

          const params = new URLSearchParams({
            query,
          });
          if (project_id) {
            params.set("project_id", project_id);
          }

          const result = await this.callBrainAPIWithAuth<{
            query: string;
            interpreted_as: string;
            events: Array<{
              id: string;
              event_type: string;
              title?: string;
              occurred_at: string;
              source_platform: string;
            }>;
            insights: string[];
            suggested_actions: string[];
          }>(
            `/api/v1/correlations/query?${params}`,
            "POST"
          );

          let output = `# Correlation Query Results\n\n`;
          output += `**Your Query:** "${result.query}"\n`;
          output += `**Interpreted As:** ${result.interpreted_as}\n\n`;

          if (result.events && result.events.length > 0) {
            output += `## Related Events (${result.events.length})\n\n`;
            output += `| Type | Title | Source | Time |\n`;
            output += `|------|-------|--------|------|\n`;

            result.events.slice(0, 20).forEach((event) => {
              const title = event.title || event.id.substring(0, 8);
              output += `| ${event.event_type} | ${title} | ${event.source_platform} | ${new Date(event.occurred_at).toLocaleString()} |\n`;
            });

            if (result.events.length > 20) {
              output += `\n_...and ${result.events.length - 20} more events_\n`;
            }
            output += `\n`;
          } else {
            output += `## No Events Found\n\nNo events matched your query.\n\n`;
          }

          if (result.insights && result.insights.length > 0) {
            output += `## Insights\n\n`;
            result.insights.forEach((insight, i) => {
              output += `${i + 1}. ${insight}\n`;
            });
            output += `\n`;
          }

          if (result.suggested_actions && result.suggested_actions.length > 0) {
            output += `## Suggested Actions\n\n`;
            result.suggested_actions.forEach((action, i) => {
              output += `${i + 1}. ${action}\n`;
            });
          }

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =====================================================
    // API TESTING TOOLS (RAP-282)
    // =====================================================

    // Tool: argus_api_discover - Discover API endpoints from OpenAPI spec
    this.server.tool(
      "argus_api_discover",
      "Discover API endpoints from an OpenAPI/Swagger specification. Parses the spec and stores discovered endpoints for test generation.",
      {
        project_id: z.string().describe("The project UUID"),
        openapi_url: z.string().describe("URL to OpenAPI/Swagger spec (JSON or YAML)"),
      },
      async ({ project_id, openapi_url }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<{
            success: boolean;
            session_id: string;
            endpoints_discovered: number;
            endpoints: Array<{
              id: string;
              path: string;
              method: string;
              operation_id?: string;
              summary?: string;
              description?: string;
              tags: string[];
              auth_type: string;
            }>;
            spec_title?: string;
            spec_version?: string;
            errors: string[];
          }>(
            "/api/v1/api-tests/discover",
            "POST",
            {
              project_id,
              openapi_url,
            }
          );

          const statusEmoji = result.success ? "✅" : result.endpoints_discovered > 0 ? "⚠️" : "❌";

          let output = `# API Discovery Results ${statusEmoji}\n\n`;
          output += `**Spec URL:** ${openapi_url}\n`;
          if (result.spec_title) output += `**API Title:** ${result.spec_title}\n`;
          if (result.spec_version) output += `**API Version:** ${result.spec_version}\n`;
          output += `**Session ID:** \`${result.session_id}\`\n\n`;

          output += `## Summary\n\n`;
          output += `- **Endpoints Discovered:** ${result.endpoints_discovered}\n`;
          output += `- **Errors:** ${result.errors.length}\n\n`;

          if (result.endpoints && result.endpoints.length > 0) {
            output += `## Discovered Endpoints\n\n`;
            output += `| Method | Path | Summary | Auth |\n`;
            output += `|--------|------|---------|------|\n`;

            result.endpoints.forEach((ep) => {
              const summary = ep.summary || ep.operation_id || "-";
              const summaryShort = summary.length > 40 ? summary.substring(0, 37) + "..." : summary;
              output += `| \`${ep.method}\` | \`${ep.path}\` | ${summaryShort} | ${ep.auth_type} |\n`;
            });
            output += `\n`;
          }

          if (result.errors.length > 0) {
            output += `## Errors\n\n`;
            result.errors.forEach((err) => {
              output += `- ${err}\n`;
            });
            output += `\n`;
          }

          output += `---\n`;
          output += `**Next Steps:**\n`;
          output += `1. Use \`argus_api_generate\` to generate test cases for discovered endpoints\n`;
          output += `2. Use \`argus_api_run\` to execute the generated tests\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_api_generate - Generate API test cases
    this.server.tool(
      "argus_api_generate",
      "Generate API test cases using AI. Creates comprehensive tests covering happy paths, error cases, edge cases, and optionally security tests.",
      {
        project_id: z.string().describe("The project UUID"),
        endpoint_ids: z.array(z.string()).optional().describe("Specific endpoint IDs to generate tests for (all if not specified)"),
        test_types: z.array(z.enum(["functional", "negative", "boundary", "security", "performance"])).optional().default(["functional", "negative", "boundary"]).describe("Types of tests to generate"),
        include_security_tests: z.boolean().optional().default(false).describe("Include security/injection tests"),
        max_tests_per_endpoint: z.number().optional().default(5).describe("Maximum tests per endpoint (1-20, default: 5)"),
      },
      async ({ project_id, endpoint_ids, test_types, include_security_tests, max_tests_per_endpoint }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<{
            success: boolean;
            tests_generated: number;
            test_cases: Array<{
              id: string;
              name: string;
              description: string;
              endpoint: string;
              method: string;
              test_type: string;
              expected_status: number;
              tags: string[];
            }>;
            generation_time_ms: number;
          }>(
            "/api/v1/api-tests/generate",
            "POST",
            {
              project_id,
              endpoint_ids: endpoint_ids || null,
              test_types: test_types || ["functional", "negative", "boundary"],
              include_security_tests: include_security_tests || false,
              max_tests_per_endpoint: max_tests_per_endpoint || 5,
            }
          );

          const statusEmoji = result.success ? "✅" : "❌";

          let output = `# API Test Generation ${statusEmoji}\n\n`;
          output += `**Tests Generated:** ${result.tests_generated}\n`;
          output += `**Generation Time:** ${result.generation_time_ms}ms\n`;
          output += `**Test Types:** ${(test_types || ["functional", "negative", "boundary"]).join(", ")}\n`;
          if (include_security_tests) output += `**Security Tests:** Included\n`;
          output += `\n`;

          if (result.test_cases && result.test_cases.length > 0) {
            // Group by endpoint
            const byEndpoint: Record<string, typeof result.test_cases> = {};
            result.test_cases.forEach((tc) => {
              const key = `${tc.method} ${tc.endpoint}`;
              if (!byEndpoint[key]) {
                byEndpoint[key] = [];
              }
              byEndpoint[key].push(tc);
            });

            output += `## Generated Tests\n\n`;

            for (const [endpoint, tests] of Object.entries(byEndpoint)) {
              output += `### ${endpoint}\n\n`;
              output += `| Test Name | Type | Expected Status |\n`;
              output += `|-----------|------|----------------|\n`;

              tests.forEach((tc) => {
                const nameShort = tc.name.length > 50 ? tc.name.substring(0, 47) + "..." : tc.name;
                output += `| ${nameShort} | ${tc.test_type} | ${tc.expected_status} |\n`;
              });
              output += `\n`;
            }
          }

          output += `---\n`;
          output += `**Next Steps:**\n`;
          output += `- Use \`argus_api_run\` to execute these tests against your API\n`;
          output += `- View and edit tests in the Skopaq dashboard\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_api_run - Execute API tests
    this.server.tool(
      "argus_api_run",
      "Execute API tests against a target URL. Validates response status codes, schemas, and latency. Returns detailed results for each test.",
      {
        project_id: z.string().describe("The project UUID"),
        base_url: z.string().describe("Base URL for API requests (e.g., https://api.example.com)"),
        test_ids: z.array(z.string()).optional().describe("Specific test IDs to run (all active tests if not specified)"),
        auth_token: z.string().optional().describe("Bearer token for authentication"),
        auth_type: z.enum(["none", "bearer", "basic", "api_key"]).optional().default("none").describe("Authentication type"),
        environment: z.string().optional().default("test").describe("Environment name for result tracking"),
        parallel: z.boolean().optional().default(false).describe("Run tests in parallel"),
        stop_on_failure: z.boolean().optional().default(false).describe("Stop execution on first failure"),
      },
      async ({ project_id, base_url, test_ids, auth_token, auth_type, environment, parallel, stop_on_failure }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<{
            success: boolean;
            run_id: string;
            total_tests: number;
            passed: number;
            failed: number;
            errors: number;
            skipped: number;
            total_duration_ms: number;
            results: Array<{
              test_id: string;
              test_name: string;
              status: string;
              duration_ms: number;
              response_status?: number;
              response_time_ms?: number;
              error_message?: string;
              schema_valid?: boolean;
            }>;
          }>(
            "/api/v1/api-tests/run",
            "POST",
            {
              project_id,
              base_url,
              test_ids: test_ids || null,
              auth_token: auth_token || null,
              auth_type: auth_type || "none",
              auth_config: {},
              environment: environment || "test",
              parallel: parallel || false,
              stop_on_failure: stop_on_failure || false,
              timeout_ms: 30000,
            }
          );

          const passRate = result.total_tests > 0
            ? ((result.passed / result.total_tests) * 100).toFixed(0)
            : "0";
          const statusEmoji = result.success ? "✅" : result.passed > 0 ? "⚠️" : "❌";
          const passRateEmoji = parseFloat(passRate) >= 90 ? "🟢" : parseFloat(passRate) >= 70 ? "🟡" : "🔴";

          let output = `# API Test Results ${statusEmoji}\n\n`;
          output += `**Run ID:** \`${result.run_id}\`\n`;
          output += `**Base URL:** ${base_url}\n`;
          output += `**Environment:** ${environment || "test"}\n`;
          output += `**Duration:** ${result.total_duration_ms}ms\n\n`;

          output += `## Summary\n\n`;
          output += `| Metric | Value |\n|--------|-------|\n`;
          output += `| Pass Rate | ${passRateEmoji} ${passRate}% |\n`;
          output += `| Total Tests | ${result.total_tests} |\n`;
          output += `| ✅ Passed | ${result.passed} |\n`;
          output += `| ❌ Failed | ${result.failed} |\n`;
          output += `| ⚠️ Errors | ${result.errors} |\n`;
          output += `| ⏭️ Skipped | ${result.skipped} |\n\n`;

          if (result.results && result.results.length > 0) {
            // Show failed tests first
            const failed = result.results.filter(r => r.status === "failed" || r.status === "error");
            const passed = result.results.filter(r => r.status === "passed");
            const other = result.results.filter(r => r.status !== "passed" && r.status !== "failed" && r.status !== "error");

            if (failed.length > 0) {
              output += `## Failed Tests (${failed.length})\n\n`;
              output += `| Test | Status | Response | Time | Error |\n`;
              output += `|------|--------|----------|------|-------|\n`;

              failed.forEach((r) => {
                const statusIcon = r.status === "failed" ? "❌" : "⚠️";
                const nameShort = r.test_name.length > 30 ? r.test_name.substring(0, 27) + "..." : r.test_name;
                const errorShort = r.error_message
                  ? (r.error_message.length > 30 ? r.error_message.substring(0, 27) + "..." : r.error_message)
                  : "-";
                output += `| ${nameShort} | ${statusIcon} ${r.status} | ${r.response_status || "-"} | ${r.response_time_ms || "-"}ms | ${errorShort} |\n`;
              });
              output += `\n`;
            }

            if (passed.length > 0 && passed.length <= 10) {
              output += `## Passed Tests (${passed.length})\n\n`;
              output += `| Test | Response | Time | Schema |\n`;
              output += `|------|----------|------|--------|\n`;

              passed.forEach((r) => {
                const nameShort = r.test_name.length > 40 ? r.test_name.substring(0, 37) + "..." : r.test_name;
                const schemaIcon = r.schema_valid === true ? "✅" : r.schema_valid === false ? "❌" : "-";
                output += `| ${nameShort} | ${r.response_status} | ${r.response_time_ms}ms | ${schemaIcon} |\n`;
              });
              output += `\n`;
            } else if (passed.length > 10) {
              output += `## Passed Tests (${passed.length})\n\n`;
              output += `_${passed.length} tests passed. View details in the dashboard._\n\n`;
            }

            if (other.length > 0) {
              output += `## Other Results (${other.length})\n\n`;
              other.forEach((r) => {
                output += `- **${r.test_name}**: ${r.status}${r.error_message ? ` - ${r.error_message}` : ""}\n`;
              });
              output += `\n`;
            }
          }

          output += `---\n`;
          output += `**Actions:**\n`;
          output += `- View detailed results in the Skopaq dashboard\n`;
          output += `- Re-run failed tests with \`argus_api_run\` and specific test_ids\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =====================================================
    // INFRASTRUCTURE & COST MANAGEMENT TOOLS
    // =====================================================

    // Tool: argus_infra_overview - Get infrastructure cost overview
    this.server.tool(
      "argus_infra_overview",
      "Get a comprehensive overview of infrastructure costs including current spend, projected costs, and comparison to BrowserStack pricing. Shows total savings achieved by self-hosting.",
      {
        days: z.number().optional().default(30).describe("Number of days to analyze (7, 30, or 90)"),
      },
      async ({ days }) => {
        try {
          await this.requireAuth();

          const [costReport, snapshot, savings] = await Promise.all([
            this.callBrainAPIWithAuth<{
              total_cost: number;
              projected_monthly: number;
              comparison_to_browserstack: number;
              savings_percentage: number;
            }>(`/api/v1/infra/cost-report?days=${days}`, "GET"),
            this.callBrainAPIWithAuth<InfraSnapshotResponse>("/api/v1/infra/snapshot", "GET"),
            this.callBrainAPIWithAuth<InfraSavingsResponse>("/api/v1/infra/savings-summary", "GET"),
          ]);

          const savingsEmoji = savings.savings_percentage > 80 ? "🟢" : savings.savings_percentage > 50 ? "🟡" : "🔴";

          let output = `# Infrastructure Cost Overview 💰\n\n`;
          output += `## Current Period (${days} days)\n\n`;
          output += `| Metric | Value |\n|--------|-------|\n`;
          output += `| Current Spend | $${costReport.total_cost.toFixed(2)} |\n`;
          output += `| Projected Monthly | $${costReport.projected_monthly.toFixed(2)} |\n`;
          output += `| BrowserStack Equivalent | $${costReport.comparison_to_browserstack.toFixed(2)} |\n`;
          output += `| ${savingsEmoji} Savings | ${savings.savings_percentage.toFixed(0)}% |\n\n`;

          output += `## Browser Pool Status\n\n`;
          output += `| Resource | Count | Utilization |\n|----------|-------|-------------|\n`;
          output += `| Total Nodes | ${snapshot.total_nodes} | ${snapshot.cluster_cpu_utilization.toFixed(0)}% CPU |\n`;
          output += `| Total Pods | ${snapshot.total_pods} | ${snapshot.cluster_memory_utilization.toFixed(0)}% Memory |\n`;
          output += `| Chrome | ${snapshot.chrome_nodes.total} | ${snapshot.chrome_nodes.utilization.toFixed(0)}% |\n`;
          output += `| Firefox | ${snapshot.firefox_nodes.total} | ${snapshot.firefox_nodes.utilization.toFixed(0)}% |\n`;
          output += `| Edge | ${snapshot.edge_nodes.total} | ${snapshot.edge_nodes.utilization.toFixed(0)}% |\n\n`;

          output += `## Savings Summary\n\n`;
          output += `- **Monthly Savings**: $${savings.savings_vs_browserstack.toFixed(2)} vs BrowserStack\n`;
          output += `- **Recommendations Applied**: ${savings.recommendations_applied}\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_infra_recommendations - Get AI-powered cost optimization recommendations
    this.server.tool(
      "argus_infra_recommendations",
      "Get AI-powered recommendations for optimizing infrastructure costs. Analyzes usage patterns and suggests scaling changes, resource optimizations, and cost-saving opportunities.",
      {},
      async () => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<InfraRecommendationsResponse>(
            "/api/v1/infra/recommendations",
            "GET"
          );

          if (!result.recommendations || result.recommendations.length === 0) {
            return {
              content: [{
                type: "text" as const,
                text: "# Infrastructure Recommendations 🤖\n\n✅ No optimization recommendations at this time. Your infrastructure is running efficiently!",
              }],
            };
          }

          let output = `# Infrastructure Recommendations 🤖\n\n`;
          output += `**Total Potential Savings**: $${result.total_potential_savings.toFixed(2)}/month\n\n`;

          result.recommendations.forEach((rec, index) => {
            const typeEmoji = {
              scale_down: "📉",
              scale_up: "📈",
              optimize: "⚡",
              alert: "⚠️",
            }[rec.type] || "💡";

            const confidenceEmoji = rec.confidence > 0.8 ? "🟢" : rec.confidence > 0.5 ? "🟡" : "🟠";

            output += `## ${index + 1}. ${typeEmoji} ${rec.title}\n\n`;
            output += `${rec.description}\n\n`;
            output += `- **Potential Savings**: $${rec.potential_savings.toFixed(2)}/month\n`;
            output += `- **Confidence**: ${confidenceEmoji} ${(rec.confidence * 100).toFixed(0)}%\n`;
            output += `- **Status**: ${rec.status}\n`;
            output += `- **Auto-applicable**: ${rec.auto_applicable ? "Yes ✅" : "No (requires approval)"}\n`;
            output += `- **ID**: \`${rec.id}\`\n\n`;
          });

          output += `---\n\n`;
          output += `To apply a recommendation: \`argus_infra_apply("recommendation_id")\`\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_infra_apply - Apply an infrastructure recommendation
    this.server.tool(
      "argus_infra_apply",
      "Apply an infrastructure optimization recommendation. Can be set to auto-apply (for safe changes) or require manual confirmation.",
      {
        recommendation_id: z.string().describe("The recommendation ID to apply"),
        auto: z.boolean().optional().default(false).describe("Whether to auto-apply without confirmation"),
      },
      async ({ recommendation_id, auto }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<{
            success: boolean;
            action_applied?: Record<string, unknown>;
            status?: string;
            error?: string;
          }>(
            `/api/v1/infra/recommendations/${recommendation_id}/apply`,
            "POST",
            { auto }
          );

          if (result.success) {
            let output = `# Recommendation Applied ✅\n\n`;
            output += `The recommendation has been successfully applied.\n\n`;
            if (result.action_applied) {
              output += `**Action taken**: ${JSON.stringify(result.action_applied, null, 2)}\n`;
            }
            return {
              content: [{ type: "text" as const, text: output }],
            };
          } else {
            return {
              content: [{
                type: "text" as const,
                text: `# Failed to Apply Recommendation ❌\n\n${result.error || "Unknown error occurred"}`,
              }],
              isError: true,
            };
          }
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_llm_usage - Get LLM/AI usage and costs
    this.server.tool(
      "argus_llm_usage",
      "Get detailed breakdown of LLM/AI usage and costs. Shows which models are being used, token consumption, and costs per feature (test generation, self-healing, etc.).",
      {
        period: z.string().optional().default("30d").describe("Period to analyze (7d, 30d, or 90d)"),
      },
      async ({ period }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<LLMUsageResponse>(
            `/api/v1/ai/usage?period=${period}`,
            "GET"
          );

          let output = `# AI / LLM Usage Report 🤖\n\n`;
          output += `**Period**: ${result.period}\n`;
          output += `**Total Cost**: $${result.total_cost.toFixed(2)}\n`;
          output += `**Total Requests**: ${result.total_requests.toLocaleString()}\n\n`;

          output += `## Usage by Model\n\n`;
          output += `| Model | Provider | Requests | Tokens (in/out) | Cost |\n`;
          output += `|-------|----------|----------|-----------------|------|\n`;

          result.models.forEach(model => {
            const tokensIn = (model.input_tokens / 1_000_000).toFixed(1) + "M";
            const tokensOut = (model.output_tokens / 1_000_000).toFixed(1) + "M";
            output += `| ${model.name} | ${model.provider} | ${model.requests.toLocaleString()} | ${tokensIn} / ${tokensOut} | $${model.cost.toFixed(2)} |\n`;
          });

          output += `\n## Usage by Feature\n\n`;
          output += `| Feature | Requests | Cost | % of Total |\n`;
          output += `|---------|----------|------|------------|\n`;

          result.features.forEach(feature => {
            output += `| ${feature.name} | ${feature.requests.toLocaleString()} | $${feature.cost.toFixed(2)} | ${feature.percentage}% |\n`;
          });

          output += `\n## Cost Optimization Tips 💡\n\n`;
          output += `- **DeepSeek** for code analysis ($0.14/1M tokens) - 90% cheaper than Claude\n`;
          output += `- **DeepSeek R1** for reasoning tasks - 10% cost of o1\n`;
          output += `- **Claude** only for Computer Use (browser automation)\n`;
          output += `- All models via **OpenRouter** - single API key, best pricing\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_browser_pool - Get real-time browser pool status
    this.server.tool(
      "argus_browser_pool",
      "Get real-time status of the Selenium Grid browser pool. Shows node status, active sessions, queue length, and utilization metrics.",
      {},
      async () => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<InfraSnapshotResponse>(
            "/api/v1/infra/snapshot",
            "GET"
          );

          const statusEmoji = result.selenium.status === "healthy" ? "🟢" : result.selenium.status === "degraded" ? "🟡" : "🔴";

          let output = `# Browser Pool Status ${statusEmoji}\n\n`;
          output += `**Status**: ${result.selenium.status.toUpperCase()}\n`;
          output += `**Timestamp**: ${result.timestamp}\n\n`;

          output += `## Selenium Grid\n\n`;
          output += `| Metric | Value |\n|--------|-------|\n`;
          output += `| Ready Nodes | ${result.selenium.ready_nodes} |\n`;
          output += `| Active Sessions | ${result.selenium.active_sessions} |\n`;
          output += `| Max Sessions | ${result.selenium.max_sessions} |\n`;
          output += `| Queue Length | ${result.selenium.queue_length} |\n\n`;

          output += `## Browser Nodes\n\n`;
          output += `| Browser | Ready | Busy | Total | Utilization |\n`;
          output += `|---------|-------|------|-------|-------------|\n`;
          output += `| 🟠 Chrome | ${result.chrome_nodes.ready} | ${result.chrome_nodes.busy} | ${result.chrome_nodes.total} | ${result.chrome_nodes.utilization.toFixed(0)}% |\n`;
          output += `| 🟠 Firefox | ${result.firefox_nodes.ready} | ${result.firefox_nodes.busy} | ${result.firefox_nodes.total} | ${result.firefox_nodes.utilization.toFixed(0)}% |\n`;
          output += `| 🔵 Edge | ${result.edge_nodes.ready} | ${result.edge_nodes.busy} | ${result.edge_nodes.total} | ${result.edge_nodes.utilization.toFixed(0)}% |\n\n`;

          output += `## Cluster Resources\n\n`;
          output += `- **CPU Utilization**: ${result.cluster_cpu_utilization.toFixed(0)}%\n`;
          output += `- **Memory Utilization**: ${result.cluster_memory_utilization.toFixed(0)}%\n`;
          output += `- **Total Pods**: ${result.total_pods}\n`;
          output += `- **Total Nodes**: ${result.total_nodes}\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // DISCOVERY & INTELLIGENT CRAWLING TOOLS
    // =========================================================================

    // Tool: argus_discovery_start - Start autonomous app crawling session
    this.server.tool(
      "argus_discovery_start",
      "Start an autonomous app crawling session. The AI agent will explore your application, discover user flows, interactive elements, and potential test scenarios. Great for understanding a new app or finding untested paths.",
      {
        project_id: z.string().describe("The project UUID to associate discovered flows with"),
        start_url: z.string().url().describe("The starting URL for the crawl (e.g., your app's homepage or login page)"),
        max_pages: z.number().optional().default(50).describe("Maximum number of pages to crawl (default: 50)"),
        timeout_seconds: z.number().optional().default(300).describe("Maximum time for the crawl session in seconds (default: 300)"),
      },
      async ({ project_id, start_url, max_pages, timeout_seconds }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<DiscoveryStartResponse>(
            "/api/v1/discovery/start",
            "POST",
            {
              project_id,
              start_url,
              max_pages,
              timeout_seconds,
            }
          );

          if (!result.success) {
            return {
              content: [{
                type: "text" as const,
                text: `## Discovery Failed\n\n${result.error || "Unknown error occurred while starting discovery session."}`,
              }],
              isError: true,
            };
          }

          let output = `## Discovery Session Started\n\n`;
          output += `**Session ID:** \`${result.session_id}\`\n`;
          output += `**Status:** ${result.status}\n`;
          output += `**Start URL:** ${start_url}\n`;
          output += `**Max Pages:** ${max_pages}\n`;
          output += `**Timeout:** ${timeout_seconds}s\n\n`;

          if (result.estimated_completion) {
            output += `**Estimated Completion:** ${result.estimated_completion}\n\n`;
          }

          output += `### Next Steps\n\n`;
          output += `1. Use \`argus_discovery_flows\` with session_id \`${result.session_id}\` to view discovered flows\n`;
          output += `2. Use \`argus_discovery_generate\` to create tests from discovered flows\n`;
          output += `3. Use \`argus_discovery_compare\` to compare with previous sessions\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_discovery_flows - Get AI-discovered user flows
    this.server.tool(
      "argus_discovery_flows",
      "Get user flows discovered by the AI crawling agent. Shows navigation paths, form submissions, and interactive sequences found during discovery. Use this to understand what the AI found in your application.",
      {
        project_id: z.string().describe("The project UUID"),
        session_id: z.string().optional().describe("Filter by specific discovery session ID (optional)"),
        limit: z.number().optional().default(20).describe("Maximum number of flows to return (default: 20)"),
      },
      async ({ project_id, session_id, limit }) => {
        try {
          await this.requireAuth();

          let endpoint = `/api/v1/discovery/flows?project_id=${project_id}&limit=${limit}`;
          if (session_id) {
            endpoint += `&session_id=${session_id}`;
          }

          const result = await this.callBrainAPIWithAuth<DiscoveryFlowsResponse>(
            endpoint,
            "GET"
          );

          if (!result.success) {
            return {
              content: [{
                type: "text" as const,
                text: `## Discovery Flows Error\n\n${result.error || "Failed to retrieve discovered flows."}`,
              }],
              isError: true,
            };
          }

          if (!result.flows || result.flows.length === 0) {
            return {
              content: [{
                type: "text" as const,
                text: `## No Flows Discovered\n\nNo user flows have been discovered yet for this project.\n\n**Tip:** Run \`argus_discovery_start\` to begin discovering flows in your application.`,
              }],
            };
          }

          let output = `## Discovered User Flows\n\n`;
          output += `**Total Flows:** ${result.total_flows}\n`;
          if (result.session_id) {
            output += `**Session:** \`${result.session_id}\`\n`;
          }
          output += `\n`;

          result.flows.forEach((flow, index) => {
            const confidenceEmoji = flow.confidence > 0.8 ? "🟢" : flow.confidence > 0.5 ? "🟡" : "🟠";

            output += `### ${index + 1}. ${flow.name}\n\n`;
            output += `**ID:** \`${flow.id}\`\n`;
            output += `**Description:** ${flow.description}\n`;
            output += `**Confidence:** ${confidenceEmoji} ${(flow.confidence * 100).toFixed(0)}%\n`;
            output += `**Entry Point:** ${flow.entry_point}\n`;
            if (flow.exit_point) {
              output += `**Exit Point:** ${flow.exit_point}\n`;
            }
            if (flow.user_journey_type) {
              output += `**Journey Type:** ${flow.user_journey_type}\n`;
            }
            output += `\n`;

            output += `**Steps (${flow.steps.length}):**\n`;
            flow.steps.slice(0, 5).forEach((step, stepIndex) => {
              output += `  ${stepIndex + 1}. ${step.action}`;
              if (step.target) output += ` on "${step.target}"`;
              if (step.value) output += ` with "${step.value}"`;
              output += `\n`;
            });
            if (flow.steps.length > 5) {
              output += `  ... and ${flow.steps.length - 5} more steps\n`;
            }
            output += `\n`;
          });

          output += `---\n\n`;
          output += `**Tip:** Use \`argus_discovery_generate\` with a flow_id to generate a test from any discovered flow.\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_discovery_generate - Generate tests from discovered flows
    this.server.tool(
      "argus_discovery_generate",
      "Generate an automated test from a discovered user flow. The AI will create test steps and assertions based on the flow's actions and expected outcomes.",
      {
        project_id: z.string().describe("The project UUID"),
        flow_id: z.string().describe("The ID of the discovered flow to generate a test from"),
        test_name: z.string().optional().describe("Custom name for the generated test (optional, AI will suggest one if not provided)"),
      },
      async ({ project_id, flow_id, test_name }) => {
        try {
          await this.requireAuth();

          const body: Record<string, unknown> = {
            project_id,
            flow_id,
          };
          if (test_name) {
            body.test_name = test_name;
          }

          const result = await this.callBrainAPIWithAuth<DiscoveryGenerateResponse>(
            "/api/v1/discovery/generate-test",
            "POST",
            body
          );

          if (!result.success) {
            return {
              content: [{
                type: "text" as const,
                text: `## Test Generation Failed\n\n${result.error || "Failed to generate test from the discovered flow."}`,
              }],
              isError: true,
            };
          }

          const confidenceEmoji = result.confidence > 0.8 ? "🟢" : result.confidence > 0.5 ? "🟡" : "🟠";

          let output = `## Test Generated Successfully\n\n`;
          output += `**Test ID:** \`${result.test.id}\`\n`;
          output += `**Name:** ${result.test.name}\n`;
          output += `**From Flow:** \`${result.flow_id}\`\n`;
          output += `**Confidence:** ${confidenceEmoji} ${(result.confidence * 100).toFixed(0)}%\n\n`;

          output += `### Description\n\n${result.test.description}\n\n`;

          output += `### Test Steps (${result.test.steps.length})\n\n`;
          result.test.steps.forEach((step, index) => {
            output += `${index + 1}. **${step.action}**`;
            if (step.target) output += ` on \`${step.target}\``;
            if (step.value) output += ` with value "${step.value}"`;
            output += `\n`;
          });

          output += `\n### Assertions (${result.test.assertions.length})\n\n`;
          result.test.assertions.forEach((assertion, index) => {
            output += `${index + 1}. ${assertion.type}`;
            if (assertion.target) output += `: \`${assertion.target}\``;
            if (assertion.expected) output += ` = "${assertion.expected}"`;
            output += `\n`;
          });

          output += `\n---\n\n`;
          output += `**Next Steps:**\n`;
          output += `- Use \`argus_test\` to run this test\n`;
          output += `- Use \`argus_test_review\` to review and approve the test\n`;
          output += `- Use \`argus_export\` to export to your preferred test framework\n`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_discovery_compare - Compare discovery sessions
    this.server.tool(
      "argus_discovery_compare",
      "Compare two discovery sessions to find new, removed, or changed user flows. Useful for detecting UI changes, new features, or regression risks between app versions.",
      {
        project_id: z.string().describe("The project UUID"),
        session_id_1: z.string().describe("The first (older/baseline) discovery session ID"),
        session_id_2: z.string().describe("The second (newer/current) discovery session ID"),
      },
      async ({ project_id, session_id_1, session_id_2 }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<DiscoveryCompareResponse>(
            `/api/v1/discovery/compare?project_id=${project_id}&session_id_1=${session_id_1}&session_id_2=${session_id_2}`,
            "GET"
          );

          if (!result.success) {
            return {
              content: [{
                type: "text" as const,
                text: `## Comparison Failed\n\n${result.error || "Failed to compare discovery sessions."}`,
              }],
              isError: true,
            };
          }

          const { comparison } = result;

          let output = `## Discovery Session Comparison\n\n`;

          output += `### Sessions\n\n`;
          output += `| Property | Session 1 (Baseline) | Session 2 (Current) |\n`;
          output += `|----------|---------------------|--------------------|\n`;
          output += `| Session ID | \`${comparison.session_1.session_id}\` | \`${comparison.session_2.session_id}\` |\n`;
          output += `| Pages | ${comparison.session_1.pages_count} | ${comparison.session_2.pages_count} |\n`;
          output += `| Flows | ${comparison.session_1.flows_count} | ${comparison.session_2.flows_count} |\n`;
          output += `| Timestamp | ${comparison.session_1.timestamp} | ${comparison.session_2.timestamp} |\n\n`;

          // New flows
          if (comparison.new_flows.length > 0) {
            output += `### New Flows (${comparison.new_flows.length})\n\n`;
            comparison.new_flows.forEach((flowId, index) => {
              output += `${index + 1}. \`${flowId}\`\n`;
            });
            output += `\n`;
          }

          // Removed flows
          if (comparison.removed_flows.length > 0) {
            output += `### Removed Flows (${comparison.removed_flows.length})\n\n`;
            comparison.removed_flows.forEach((flowId, index) => {
              output += `${index + 1}. \`${flowId}\`\n`;
            });
            output += `\n`;
          }

          // Changed flows
          if (comparison.changed_flows.length > 0) {
            output += `### Changed Flows (${comparison.changed_flows.length})\n\n`;
            comparison.changed_flows.forEach((changed, index) => {
              output += `${index + 1}. **\`${changed.flow_id}\`**\n`;
              changed.changes.forEach(change => {
                output += `   - ${change}\n`;
              });
            });
            output += `\n`;
          }

          // Summary
          output += `### Summary\n\n${comparison.summary}\n\n`;

          // Recommendations
          const hasChanges = comparison.new_flows.length > 0 || comparison.removed_flows.length > 0 || comparison.changed_flows.length > 0;

          if (hasChanges) {
            output += `### Recommendations\n\n`;
            if (comparison.new_flows.length > 0) {
              output += `- **Generate tests** for ${comparison.new_flows.length} new flow(s) using \`argus_discovery_generate\`\n`;
            }
            if (comparison.removed_flows.length > 0) {
              output += `- **Review removed flows** - these may indicate deprecated features or broken navigation\n`;
            }
            if (comparison.changed_flows.length > 0) {
              output += `- **Update existing tests** for ${comparison.changed_flows.length} changed flow(s) to prevent test failures\n`;
            }
          } else {
            output += `No significant changes detected between sessions.\n`;
          }

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // TIME TRAVEL DEBUGGING TOOLS - Execution history and replay
    // =========================================================================

    // Tool: argus_time_travel_checkpoints - List state checkpoints for a test run
    this.server.tool(
      "argus_time_travel_checkpoints",
      "List all state checkpoints for a test run. Use this to browse historical execution states and find points to replay or fork from.",
      {
        project_id: z.string().describe("The project UUID to list checkpoints for"),
        thread_id: z.string().optional().describe("Optional thread ID to filter checkpoints for a specific execution"),
        limit: z.number().optional().describe("Maximum number of checkpoints to return (default: 20)"),
      },
      async ({ project_id, thread_id, limit = 20 }) => {
        try {
          await this.requireAuth();

          let url = `/api/v1/time-travel/checkpoints?project_id=${project_id}&limit=${limit}`;
          if (thread_id) {
            url += `&thread_id=${thread_id}`;
          }

          const result = await this.callBrainAPIWithAuth<TimeTravelCheckpointsResponse>(
            url,
            "GET"
          );

          if (!result.checkpoints || result.checkpoints.length === 0) {
            return {
              content: [{
                type: "text" as const,
                text: `## Time Travel Checkpoints\n\nNo checkpoints found for project \`${project_id}\`${thread_id ? ` and thread \`${thread_id}\`` : ""}.\n\n**Tip:** Checkpoints are created automatically during test execution. Run some tests first to create execution history.`,
              }],
            };
          }

          const checkpointsList = result.checkpoints.map((cp, i) => {
            const summary = cp.state_summary;
            const summaryText = summary
              ? `Tests: ${summary.test_count ?? "N/A"}, Failures: ${summary.failures_count ?? 0}${summary.current_step ? `, Step: ${summary.current_step}` : ""}`
              : "No state summary";
            return `${i + 1}. **${cp.node_name}** (${new Date(cp.created_at).toLocaleString()})\n   ID: \`${cp.checkpoint_id}\`\n   Thread: \`${cp.thread_id}\`\n   ${summaryText}`;
          }).join("\n\n");

          return {
            content: [{
              type: "text" as const,
              text: `## Time Travel Checkpoints\n\n**Project:** \`${project_id}\`\n**Total:** ${result.total} checkpoints\n\n${checkpointsList}\n\n---\n**Actions:**\n- Use \`argus_time_travel_history\` to see detailed state changes\n- Use \`argus_time_travel_replay\` to replay from a checkpoint\n- Use \`argus_time_travel_fork\` to create a branch for A/B testing`,
            }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_time_travel_history - View state change history for a thread
    this.server.tool(
      "argus_time_travel_history",
      "View the complete state change history for a specific execution thread. Shows transitions between nodes and what changed at each step.",
      {
        thread_id: z.string().describe("The thread ID to view history for"),
        include_state: z.boolean().optional().describe("Include full state snapshots at each checkpoint (default: false)"),
      },
      async ({ thread_id, include_state = false }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<TimeTravelHistoryResponse>(
            `/api/v1/time-travel/history/${thread_id}?include_state=${include_state}`,
            "GET"
          );

          if (!result.history || result.history.length === 0) {
            return {
              content: [{
                type: "text" as const,
                text: `## Execution History\n\nNo history found for thread \`${thread_id}\`.\n\n**Tip:** Make sure the thread ID is correct and the execution has completed.`,
              }],
            };
          }

          const historyList = result.history.map((entry, i) => {
            const transitionText = entry.transition_from
              ? `${entry.transition_from} -> ${entry.node_name}`
              : `START -> ${entry.node_name}`;

            let changesText = "";
            if (entry.changes && entry.changes.length > 0) {
              changesText = "\n   Changes:\n" + entry.changes.slice(0, 5).map(c =>
                `   - \`${c.field}\`: ${JSON.stringify(c.old_value)} -> ${JSON.stringify(c.new_value)}`
              ).join("\n");
              if (entry.changes.length > 5) {
                changesText += `\n   ... and ${entry.changes.length - 5} more changes`;
              }
            }

            let stateText = "";
            if (include_state && entry.state) {
              const statePreview = JSON.stringify(entry.state, null, 2).slice(0, 500);
              stateText = `\n   State (preview):\n   \`\`\`json\n   ${statePreview}${statePreview.length >= 500 ? "..." : ""}\n   \`\`\``;
            }

            return `### ${i + 1}. ${transitionText}\n**Time:** ${new Date(entry.created_at).toLocaleString()}\n**Checkpoint:** \`${entry.checkpoint_id}\`${changesText}${stateText}`;
          }).join("\n\n");

          return {
            content: [{
              type: "text" as const,
              text: `## Execution History for Thread \`${thread_id}\`\n\n**Total Entries:** ${result.total_entries}\n\n${historyList}\n\n---\n**Tip:** Use \`argus_time_travel_replay\` with a checkpoint_id to replay from any point.`,
            }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_time_travel_replay - Replay execution from a checkpoint
    this.server.tool(
      "argus_time_travel_replay",
      "Replay test execution from a specific checkpoint. Creates a new execution thread starting from the saved state. Optionally modify state before replay.",
      {
        checkpoint_id: z.string().describe("The checkpoint ID to replay from"),
        modifications: z.object({}).passthrough().optional().describe("Optional state modifications to apply before replay (e.g., change test inputs)"),
      },
      async ({ checkpoint_id, modifications }) => {
        try {
          await this.requireAuth();

          const body: Record<string, unknown> = { checkpoint_id };
          if (modifications) {
            body.modifications = modifications;
          }

          const result = await this.callBrainAPIWithAuth<TimeTravelReplayResponse>(
            "/api/v1/time-travel/replay",
            "POST",
            body
          );

          if (!result.success) {
            return {
              content: [{
                type: "text" as const,
                text: `## Replay Failed\n\n**Error:** ${result.message || "Unknown error"}\n\n**Checkpoint:** \`${checkpoint_id}\`\n\n**Tip:** Make sure the checkpoint exists and the state is valid for replay.`,
              }],
              isError: true,
            };
          }

          const modText = modifications
            ? `\n**Modifications Applied:**\n\`\`\`json\n${JSON.stringify(modifications, null, 2)}\n\`\`\``
            : "";

          return {
            content: [{
              type: "text" as const,
              text: `## Replay Started Successfully\n\n**New Thread ID:** \`${result.new_thread_id}\`\n**From Checkpoint:** \`${result.checkpoint_id}\`\n**Status:** ${result.status}${modText}\n\n---\n**Next Steps:**\n- Use \`argus_time_travel_checkpoints\` to monitor the new execution\n- Use \`argus_time_travel_compare\` to compare with the original execution`,
            }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_time_travel_fork - Fork execution for A/B testing
    this.server.tool(
      "argus_time_travel_fork",
      "Fork an execution from a checkpoint to create a branch for A/B testing. The forked execution can be modified independently to test different scenarios.",
      {
        checkpoint_id: z.string().describe("The checkpoint ID to fork from"),
        branch_name: z.string().optional().describe("Optional name for the forked branch (e.g., 'experiment-new-selector')"),
      },
      async ({ checkpoint_id, branch_name }) => {
        try {
          await this.requireAuth();

          const body: Record<string, unknown> = { checkpoint_id };
          if (branch_name) {
            body.branch_name = branch_name;
          }

          const result = await this.callBrainAPIWithAuth<TimeTravelForkResponse>(
            "/api/v1/time-travel/fork",
            "POST",
            body
          );

          if (!result.success) {
            return {
              content: [{
                type: "text" as const,
                text: `## Fork Failed\n\n**Error:** ${result.message || "Unknown error"}\n\n**Checkpoint:** \`${checkpoint_id}\``,
              }],
              isError: true,
            };
          }

          return {
            content: [{
              type: "text" as const,
              text: `## Fork Created Successfully\n\n**Forked Thread ID:** \`${result.forked_thread_id}\`\n**Branch Name:** ${result.branch_name || "(default)"}\n**From Checkpoint:** \`${result.checkpoint_id}\`\n\n---\n**A/B Testing Tips:**\n- Run different test variations on the forked thread\n- Use \`argus_time_travel_compare\` to compare results\n- Use \`argus_time_travel_replay\` with modifications to test different inputs`,
            }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_time_travel_compare - Compare divergent execution paths
    this.server.tool(
      "argus_time_travel_compare",
      "Compare two execution threads to see where they diverged and what differences exist. Useful for A/B testing analysis and debugging.",
      {
        thread_id_1: z.string().describe("First thread ID to compare"),
        thread_id_2: z.string().describe("Second thread ID to compare"),
      },
      async ({ thread_id_1, thread_id_2 }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<TimeTravelCompareResponse>(
            `/api/v1/time-travel/compare/${thread_id_1}/${thread_id_2}`,
            "GET"
          );

          let divergenceText = "No common divergence point found (threads may be unrelated).";
          if (result.divergence_point) {
            divergenceText = `**Divergence Point:**\n- Checkpoint: \`${result.divergence_point.checkpoint_id}\`\n- Node: ${result.divergence_point.node_name}\n- Time: ${new Date(result.divergence_point.timestamp).toLocaleString()}`;
          }

          let differencesText = "No differences found.";
          if (result.differences && result.differences.length > 0) {
            differencesText = result.differences.slice(0, 10).map((diff, i) => {
              return `${i + 1}. **${diff.field}**\n   Thread 1: \`${JSON.stringify(diff.thread_1_value)}\`\n   Thread 2: \`${JSON.stringify(diff.thread_2_value)}\`\n   First diverged: ${new Date(diff.first_diverged_at).toLocaleString()}`;
            }).join("\n\n");

            if (result.differences.length > 10) {
              differencesText += `\n\n... and ${result.differences.length - 10} more differences`;
            }
          }

          return {
            content: [{
              type: "text" as const,
              text: `## Execution Comparison\n\n**Thread 1:** \`${result.thread_id_1}\` (${result.summary.thread_1_steps} steps)\n**Thread 2:** \`${result.thread_id_2}\` (${result.summary.thread_2_steps} steps)\n\n${divergenceText}\n\n### Differences (${result.summary.total_differences} total)\n\n${differencesText}\n\n---\n**Tip:** Use \`argus_time_travel_history\` on each thread to see detailed state changes.`,
            }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =====================================================
    // SCHEDULING & AUTOMATION TOOLS (RAP-280)
    // =====================================================

    // Tool: argus_schedule_create - Create a test schedule
    this.server.tool(
      "argus_schedule_create",
      "Create a scheduled test run. Define when tests should run automatically using cron expressions (e.g., '0 9 * * *' for daily at 9 AM UTC). Schedules can be enabled/disabled without deletion.",
      {
        project_id: z.string().describe("The project UUID"),
        name: z.string().describe("A descriptive name for the schedule (e.g., 'Nightly Regression Suite')"),
        cron_expression: z.string().describe("Cron expression for schedule timing (e.g., '0 9 * * *' for daily at 9 AM, '0 */4 * * *' for every 4 hours)"),
        test_ids: z.array(z.string()).describe("Array of test IDs to run on this schedule"),
        enabled: z.boolean().optional().default(true).describe("Whether the schedule is active (default: true)"),
      },
      async ({ project_id, name, cron_expression, test_ids, enabled }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<ScheduleCreateResponse>(
            "/api/v1/schedules",
            "POST",
            {
              project_id,
              name,
              cron_expression,
              test_ids,
              enabled,
            }
          );

          if (!result.success) {
            return {
              content: [{
                type: "text" as const,
                text: `## Schedule Creation Failed\n\n**Error:** ${result.error || "Unknown error"}\n\n**Tips:**\n- Verify cron expression syntax (e.g., \`0 9 * * *\` for daily at 9 AM)\n- Ensure all test IDs exist in the project\n- Check project permissions`,
              }],
              isError: true,
            };
          }

          const schedule = result.schedule;
          const statusEmoji = schedule.enabled ? "🟢 Active" : "🔴 Disabled";

          let output = `## Schedule Created Successfully\n\n`;
          output += `| Field | Value |\n|-------|-------|\n`;
          output += `| **ID** | \`${schedule.id}\` |\n`;
          output += `| **Name** | ${schedule.name} |\n`;
          output += `| **Status** | ${statusEmoji} |\n`;
          output += `| **Cron Expression** | \`${schedule.cron_expression}\` |\n`;
          output += `| **Tests** | ${schedule.test_ids.length} test(s) |\n`;
          if (schedule.next_run_at) {
            output += `| **Next Run** | ${new Date(schedule.next_run_at).toLocaleString()} |\n`;
          }
          output += `| **Created** | ${new Date(schedule.created_at).toLocaleString()} |\n`;

          output += `\n### Test IDs\n\n`;
          schedule.test_ids.forEach((testId, i) => {
            output += `${i + 1}. \`${testId}\`\n`;
          });

          output += `\n---\n**Next Steps:**\n`;
          output += `- \`argus_schedule_list("${project_id}")\` - View all schedules\n`;
          output += `- \`argus_schedule_run("${schedule.id}")\` - Trigger manually\n`;
          output += `- \`argus_schedule_history("${schedule.id}")\` - View run history`;

          return {
            content: [{
              type: "text" as const,
              text: output,
            }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_schedule_list - List schedules for a project
    this.server.tool(
      "argus_schedule_list",
      "List all test schedules for a project. Shows schedule status, timing, and next run information. Filter by enabled/disabled status.",
      {
        project_id: z.string().describe("The project UUID"),
        limit: z.number().optional().default(20).describe("Maximum number of schedules to return (default: 20)"),
        status: z.enum(["enabled", "disabled"]).optional().describe("Filter by schedule status (enabled/disabled)"),
      },
      async ({ project_id, limit, status }) => {
        try {
          await this.requireAuth();

          let url = `/api/v1/schedules?project_id=${project_id}&limit=${limit}`;
          if (status) {
            url += `&status=${status}`;
          }

          const result = await this.callBrainAPIWithAuth<ScheduleResponse>(
            url,
            "GET"
          );

          if (!result.schedules || result.schedules.length === 0) {
            return {
              content: [{
                type: "text" as const,
                text: `## Schedules for Project\n\nNo schedules found${status ? ` with status "${status}"` : ""}.\n\n**Create a schedule:**\n\`\`\`\nargus_schedule_create(\n  project_id: "${project_id}",\n  name: "Nightly Regression",\n  cron_expression: "0 2 * * *",  // Daily at 2 AM\n  test_ids: ["test-id-1", "test-id-2"]\n)\n\`\`\``,
              }],
            };
          }

          let output = `## Test Schedules\n\n`;
          output += `**Project:** \`${project_id}\`\n`;
          output += `**Total:** ${result.schedules.length} schedule(s)\n\n`;

          output += `| Name | Status | Cron | Tests | Next Run | Last Run |\n`;
          output += `|------|--------|------|-------|----------|----------|\n`;

          result.schedules.forEach((schedule) => {
            const statusEmoji = schedule.enabled ? "🟢" : "🔴";
            const nextRun = schedule.next_run_at
              ? new Date(schedule.next_run_at).toLocaleString()
              : "N/A";
            const lastRun = schedule.last_run_at
              ? new Date(schedule.last_run_at).toLocaleString()
              : "Never";
            output += `| ${schedule.name} | ${statusEmoji} | \`${schedule.cron_expression}\` | ${schedule.test_ids.length} | ${nextRun} | ${lastRun} |\n`;
          });

          output += `\n### Schedule Details\n\n`;
          result.schedules.forEach((schedule, i) => {
            const statusText = schedule.enabled ? "Active" : "Disabled";
            output += `**${i + 1}. ${schedule.name}** (${statusText})\n`;
            output += `- ID: \`${schedule.id}\`\n`;
            output += `- Cron: \`${schedule.cron_expression}\`\n`;
            output += `- Tests: ${schedule.test_ids.length} test(s)\n\n`;
          });

          output += `---\n**Actions:**\n`;
          output += `- \`argus_schedule_run("schedule_id")\` - Trigger a schedule manually\n`;
          output += `- \`argus_schedule_history("schedule_id")\` - View run history\n`;
          output += `- \`argus_schedule_create(...)\` - Create a new schedule`;

          return {
            content: [{
              type: "text" as const,
              text: output,
            }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_schedule_run - Manually trigger a schedule
    this.server.tool(
      "argus_schedule_run",
      "Manually trigger a test schedule to run immediately, bypassing the cron timing. Useful for testing schedule configuration or running tests on demand.",
      {
        schedule_id: z.string().describe("The schedule UUID to trigger"),
      },
      async ({ schedule_id }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<ScheduleRunResponse>(
            `/api/v1/schedules/${schedule_id}/trigger`,
            "POST"
          );

          if (!result.success) {
            return {
              content: [{
                type: "text" as const,
                text: `## Schedule Trigger Failed\n\n**Schedule ID:** \`${schedule_id}\`\n**Error:** ${result.error || "Unknown error"}\n\n**Possible causes:**\n- Schedule does not exist\n- Schedule is disabled\n- Concurrent run already in progress`,
              }],
              isError: true,
            };
          }

          const statusEmoji = result.status === "running" ? "🔄" : result.status === "queued" ? "⏳" : "✅";

          let output = `## Schedule Triggered Successfully ${statusEmoji}\n\n`;
          output += `| Field | Value |\n|-------|-------|\n`;
          output += `| **Run ID** | \`${result.run_id}\` |\n`;
          output += `| **Schedule ID** | \`${result.schedule_id}\` |\n`;
          output += `| **Status** | ${result.status} |\n`;
          output += `| **Started At** | ${new Date(result.started_at).toLocaleString()} |\n`;

          if (result.message) {
            output += `\n**Message:** ${result.message}\n`;
          }

          output += `\n---\n**Monitor progress:**\n`;
          output += `- \`argus_schedule_history("${schedule_id}")\` - View run results\n`;
          output += `- Check the Skopaq dashboard for real-time updates`;

          return {
            content: [{
              type: "text" as const,
              text: output,
            }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_schedule_history - View run history for a schedule
    this.server.tool(
      "argus_schedule_history",
      "View the execution history for a test schedule. Shows past runs with their status, duration, and test results. Useful for monitoring schedule health and identifying flaky tests.",
      {
        schedule_id: z.string().describe("The schedule UUID to view history for"),
        limit: z.number().optional().default(20).describe("Maximum number of runs to return (default: 20)"),
      },
      async ({ schedule_id, limit }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<ScheduleHistoryResponse>(
            `/api/v1/schedules/${schedule_id}/runs?limit=${limit}`,
            "GET"
          );

          if (!result.success) {
            return {
              content: [{
                type: "text" as const,
                text: `## Schedule History Error\n\n**Schedule ID:** \`${schedule_id}\`\n**Error:** Schedule not found or access denied.`,
              }],
              isError: true,
            };
          }

          if (!result.runs || result.runs.length === 0) {
            return {
              content: [{
                type: "text" as const,
                text: `## Schedule Run History\n\n**Schedule ID:** \`${schedule_id}\`\n\nNo runs found for this schedule.\n\n**Trigger a run:**\n\`argus_schedule_run("${schedule_id}")\``,
              }],
            };
          }

          let output = `## Schedule Run History\n\n`;
          output += `**Schedule ID:** \`${schedule_id}\`\n`;
          output += `**Total Runs:** ${result.total}\n\n`;

          output += `| Run | Status | Started | Duration | Tests | Passed | Failed |\n`;
          output += `|-----|--------|---------|----------|-------|--------|--------|\n`;

          result.runs.forEach((run, i) => {
            const statusEmoji = run.status === "completed" && run.tests_failed === 0 ? "✅" :
                               run.status === "completed" && run.tests_failed > 0 ? "⚠️" :
                               run.status === "running" ? "🔄" :
                               run.status === "failed" ? "❌" : "⏳";
            const duration = run.duration_ms ? `${(run.duration_ms / 1000).toFixed(1)}s` : "-";
            const started = new Date(run.started_at).toLocaleString();
            output += `| ${i + 1} | ${statusEmoji} ${run.status} | ${started} | ${duration} | ${run.tests_run} | ${run.tests_passed} | ${run.tests_failed} |\n`;
          });

          // Calculate summary stats
          const completedRuns = result.runs.filter(r => r.status === "completed");
          const successfulRuns = completedRuns.filter(r => r.tests_failed === 0).length;
          const successRate = completedRuns.length > 0
            ? ((successfulRuns / completedRuns.length) * 100).toFixed(1)
            : "N/A";
          const avgDuration = completedRuns.length > 0 && completedRuns[0].duration_ms
            ? (completedRuns.reduce((sum, r) => sum + (r.duration_ms || 0), 0) / completedRuns.length / 1000).toFixed(1)
            : "N/A";

          output += `\n### Summary\n\n`;
          output += `- **Success Rate:** ${successRate}%\n`;
          output += `- **Avg Duration:** ${avgDuration}s\n`;
          output += `- **Completed Runs:** ${completedRuns.length}\n`;

          // Show any errors from recent failed runs
          const failedRuns = result.runs.filter(r => r.status === "failed" || r.tests_failed > 0);
          if (failedRuns.length > 0) {
            output += `\n### Recent Issues\n\n`;
            failedRuns.slice(0, 3).forEach((run) => {
              const runDate = new Date(run.started_at).toLocaleDateString();
              if (run.error) {
                output += `- **${runDate}:** ${run.error}\n`;
              } else if (run.tests_failed > 0) {
                output += `- **${runDate}:** ${run.tests_failed} test(s) failed\n`;
              }
            });
          }

          output += `\n---\n**Actions:**\n`;
          output += `- \`argus_schedule_run("${schedule_id}")\` - Trigger a new run\n`;
          output += `- \`argus_schedule_list("project_id")\` - View all schedules`;

          return {
            content: [{
              type: "text" as const,
              text: output,
            }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );


    // =====================================================
    // VISUAL AI TESTING TOOLS (RAP-279)
    // =====================================================

    // Tool: argus_visual_capture - Capture screenshot with metadata
    this.server.tool(
      "argus_visual_capture",
      "Capture a screenshot of a web page with metadata. Useful for visual regression testing, creating baselines, and documenting UI states.",
      {
        project_id: z.string().describe("The project UUID"),
        url: z.string().url().describe("URL of the page to capture"),
        viewport: z.object({
          width: z.number().min(320).max(3840).optional().default(1920).describe("Viewport width in pixels (default: 1920)"),
          height: z.number().min(240).max(2160).optional().default(1080).describe("Viewport height in pixels (default: 1080)"),
        }).optional().describe("Viewport dimensions for the screenshot"),
        fullpage: z.boolean().optional().default(false).describe("Capture full page including scrollable content (default: false)"),
      },
      async ({ project_id, url, viewport, fullpage }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<VisualCaptureResponse>(
            "/api/v1/visual/capture",
            "POST",
            {
              project_id,
              url,
              viewport: viewport || { width: 1920, height: 1080 },
              fullpage: fullpage || false,
            }
          );

          if (!result.success) {
            return {
              content: [{
                type: "text" as const,
                text: `## Screenshot Capture Failed\n\n**Error:** ${result.error || "Unknown error"}\n**URL:** ${url}`,
              }],
              isError: true,
            };
          }

          let output = `## Screenshot Captured\n\n`;
          output += `**Screenshot ID:** \`${result.screenshot_id}\`\n`;
          output += `**URL:** ${result.url}\n`;
          output += `**Viewport:** ${result.viewport.width}x${result.viewport.height}\n`;
          output += `**Captured At:** ${new Date(result.captured_at).toLocaleString()}\n\n`;

          if (result.metadata) {
            output += `### Page Metadata\n\n`;
            if (result.metadata.title) output += `- **Title:** ${result.metadata.title}\n`;
            if (result.metadata.load_time_ms) output += `- **Load Time:** ${result.metadata.load_time_ms}ms\n`;
            if (result.metadata.dom_elements) output += `- **DOM Elements:** ${result.metadata.dom_elements}\n`;
            output += `\n`;
          }

          output += `### Screenshot URL\n\n`;
          output += `![Screenshot](${result.screenshot_url})\n\n`;
          output += `**Direct Link:** [View Screenshot](${result.screenshot_url})\n\n`;

          output += `---\n**Next Steps:**\n`;
          output += `- Use \`argus_visual_baseline\` to set this as a baseline\n`;
          output += `- Use \`argus_visual_analyze\` for AI-powered visual analysis\n`;
          output += `- Use \`argus_visual_compare\` to diff against another screenshot`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_visual_compare - AI-powered visual diff
    this.server.tool(
      "argus_visual_compare",
      "AI-powered visual comparison between screenshots. Detects visual differences, categorizes changes by severity, and provides intelligent analysis of what changed.",
      {
        project_id: z.string().describe("The project UUID"),
        baseline_id: z.string().optional().describe("Baseline screenshot ID (use this OR baseline_url)"),
        screenshot_id: z.string().optional().describe("Screenshot ID to compare (use this OR compare_url)"),
        baseline_url: z.string().url().optional().describe("URL to capture as baseline (use if baseline_id not provided)"),
        compare_url: z.string().url().optional().describe("URL to capture for comparison (use if screenshot_id not provided)"),
      },
      async ({ project_id, baseline_id, screenshot_id, baseline_url, compare_url }) => {
        try {
          await this.requireAuth();

          // Validate input - need either IDs or URLs
          if (!baseline_id && !baseline_url) {
            return {
              content: [{
                type: "text" as const,
                text: `## Input Error\n\nPlease provide either \`baseline_id\` or \`baseline_url\` for the baseline screenshot.`,
              }],
              isError: true,
            };
          }

          if (!screenshot_id && !compare_url) {
            return {
              content: [{
                type: "text" as const,
                text: `## Input Error\n\nPlease provide either \`screenshot_id\` or \`compare_url\` for the comparison screenshot.`,
              }],
              isError: true,
            };
          }

          const body: Record<string, unknown> = { project_id };
          if (baseline_id) body.baseline_id = baseline_id;
          if (screenshot_id) body.screenshot_id = screenshot_id;
          if (baseline_url) body.baseline_url = baseline_url;
          if (compare_url) body.compare_url = compare_url;

          const result = await this.callBrainAPIWithAuth<VisualCompareResponse>(
            "/api/v1/visual/compare",
            "POST",
            body
          );

          if (!result.success) {
            return {
              content: [{
                type: "text" as const,
                text: `## Visual Comparison Failed\n\n**Error:** ${result.error || "Unknown error"}`,
              }],
              isError: true,
            };
          }

          const matchEmoji = result.is_match ? "✅" : "❌";
          const matchPercentEmoji = result.match_percentage > 95 ? "🟢" : result.match_percentage > 80 ? "🟡" : "🔴";

          let output = `## Visual Comparison Results ${matchEmoji}\n\n`;
          output += `**Comparison ID:** \`${result.comparison_id}\`\n`;
          output += `**Match:** ${matchPercentEmoji} ${result.match_percentage.toFixed(1)}%\n`;
          output += `**Status:** ${result.is_match ? "Screenshots match" : "Differences detected"}\n`;
          output += `**Analysis Time:** ${result.comparison_time_ms}ms\n\n`;

          if (result.differences && result.differences.length > 0) {
            output += `### Differences Detected (${result.differences.length})\n\n`;
            output += `| Region | Type | Severity | Description |\n|--------|------|----------|-------------|\n`;

            result.differences.slice(0, 10).forEach((diff) => {
              const severityEmoji = diff.severity === "high" ? "🔴" : diff.severity === "medium" ? "🟡" : "🟢";
              const regionStr = `(${diff.region.x}, ${diff.region.y}) ${diff.region.width}x${diff.region.height}`;
              output += `| ${regionStr} | ${diff.type} | ${severityEmoji} ${diff.severity} | ${diff.description} |\n`;
            });

            if (result.differences.length > 10) {
              output += `\n_...and ${result.differences.length - 10} more differences_\n`;
            }
            output += `\n`;
          }

          if (result.ai_analysis) {
            output += `### AI Analysis\n\n`;
            output += `**Summary:** ${result.ai_analysis.summary}\n\n`;

            if (result.ai_analysis.visual_changes && result.ai_analysis.visual_changes.length > 0) {
              output += `**Visual Changes:**\n`;
              result.ai_analysis.visual_changes.forEach((change) => {
                output += `- ${change}\n`;
              });
              output += `\n`;
            }

            output += `**Impact Assessment:** ${result.ai_analysis.impact_assessment}\n\n`;
            output += `**Recommendation:** ${result.ai_analysis.recommendation}\n\n`;
          }

          if (result.diff_image_url) {
            output += `### Diff Image\n\n`;
            output += `![Visual Diff](${result.diff_image_url})\n\n`;
            output += `**Direct Link:** [View Diff Image](${result.diff_image_url})\n\n`;
          }

          output += `---\n**IDs for Reference:**\n`;
          output += `- Baseline: \`${result.baseline_id}\`\n`;
          output += `- Screenshot: \`${result.screenshot_id}\``;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_visual_baseline - Set a visual baseline
    this.server.tool(
      "argus_visual_baseline",
      "Set a screenshot as a visual baseline for future comparisons. Baselines are named reference screenshots that new screenshots can be compared against.",
      {
        project_id: z.string().describe("The project UUID"),
        screenshot_id: z.string().describe("Screenshot ID to set as baseline"),
        name: z.string().describe("Name for the baseline (e.g., 'Homepage Desktop', 'Checkout Flow Step 2')"),
        description: z.string().optional().describe("Optional description of what this baseline represents"),
      },
      async ({ project_id, screenshot_id, name, description }) => {
        try {
          await this.requireAuth();

          const body: Record<string, unknown> = {
            project_id,
            screenshot_id,
            name,
          };
          if (description) body.description = description;

          const result = await this.callBrainAPIWithAuth<VisualBaselineResponse>(
            "/api/v1/visual/baseline",
            "POST",
            body
          );

          if (!result.success) {
            return {
              content: [{
                type: "text" as const,
                text: `## Baseline Creation Failed\n\n**Error:** ${result.error || "Unknown error"}\n**Screenshot ID:** \`${screenshot_id}\``,
              }],
              isError: true,
            };
          }

          let output = `## Baseline Created\n\n`;
          output += `**Baseline ID:** \`${result.baseline_id}\`\n`;
          output += `**Name:** ${result.name}\n`;
          if (result.description) output += `**Description:** ${result.description}\n`;
          output += `**Screenshot ID:** \`${result.screenshot_id}\`\n`;
          output += `**Created At:** ${new Date(result.created_at).toLocaleString()}\n\n`;

          output += `### Baseline Screenshot\n\n`;
          output += `![Baseline](${result.screenshot_url})\n\n`;
          output += `**Direct Link:** [View Baseline](${result.screenshot_url})\n\n`;

          output += `---\n**Usage:**\n`;
          output += `\`\`\`\n`;
          output += `argus_visual_compare(\n`;
          output += `  project_id: "${project_id}",\n`;
          output += `  baseline_id: "${result.baseline_id}",\n`;
          output += `  compare_url: "https://your-site.com/page-to-test"\n`;
          output += `)\n`;
          output += `\`\`\``;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_visual_baselines - List visual baselines
    this.server.tool(
      "argus_visual_baselines",
      "List all visual baselines for a project. Shows baseline names, screenshots, and comparison counts.",
      {
        project_id: z.string().describe("The project UUID"),
        limit: z.number().optional().default(20).describe("Maximum number of baselines to return (default: 20)"),
      },
      async ({ project_id, limit }) => {
        try {
          await this.requireAuth();

          const params = new URLSearchParams({
            project_id,
            limit: String(limit || 20),
          });

          const result = await this.callBrainAPIWithAuth<VisualBaselinesResponse>(
            `/api/v1/visual/baselines?${params}`,
            "GET"
          );

          if (!result.baselines || result.baselines.length === 0) {
            return {
              content: [{
                type: "text" as const,
                text: `## No Visual Baselines Found\n\nNo baselines exist for this project yet.\n\n**To create a baseline:**\n1. Use \`argus_visual_capture\` to capture a screenshot\n2. Use \`argus_visual_baseline\` to set it as a baseline`,
              }],
            };
          }

          let output = `## Visual Baselines\n\n`;
          output += `**Project:** \`${result.project_id}\`\n`;
          output += `**Total Baselines:** ${result.total}\n\n`;

          output += `| Name | URL | Viewport | Created | Comparisons |\n|------|-----|----------|---------|-------------|\n`;

          result.baselines.forEach((baseline) => {
            const createdDate = new Date(baseline.created_at).toLocaleDateString();
            const viewport = `${baseline.viewport.width}x${baseline.viewport.height}`;
            const urlShort = baseline.url.length > 40 ? baseline.url.substring(0, 37) + "..." : baseline.url;
            output += `| [${baseline.name}](${baseline.screenshot_url}) | ${urlShort} | ${viewport} | ${createdDate} | ${baseline.comparison_count} |\n`;
          });

          output += `\n### Baseline Details\n\n`;

          result.baselines.slice(0, 5).forEach((baseline, i) => {
            output += `**${i + 1}. ${baseline.name}**\n`;
            output += `- ID: \`${baseline.id}\`\n`;
            output += `- URL: ${baseline.url}\n`;
            if (baseline.description) output += `- Description: ${baseline.description}\n`;
            output += `- Viewport: ${baseline.viewport.width}x${baseline.viewport.height}\n`;
            output += `- Comparisons: ${baseline.comparison_count}\n\n`;
          });

          if (result.baselines.length > 5) {
            output += `_...and ${result.baselines.length - 5} more baselines_\n\n`;
          }

          output += `---\n**Actions:**\n`;
          output += `- Use \`argus_visual_compare\` with a baseline_id to compare against new screenshots\n`;
          output += `- Use \`argus_visual_capture\` to capture new screenshots for comparison`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // Tool: argus_visual_analyze - Analyze visual changes with WCAG accessibility
    this.server.tool(
      "argus_visual_analyze",
      "AI-powered visual analysis of a screenshot. Identifies UI elements, assesses layout structure, and optionally performs WCAG accessibility compliance checks.",
      {
        project_id: z.string().describe("The project UUID"),
        screenshot_id: z.string().describe("Screenshot ID to analyze"),
        include_wcag: z.boolean().optional().default(true).describe("Include WCAG accessibility compliance check (default: true)"),
      },
      async ({ project_id, screenshot_id, include_wcag }) => {
        try {
          await this.requireAuth();

          const result = await this.callBrainAPIWithAuth<VisualAnalyzeResponse>(
            "/api/v1/visual/analyze",
            "POST",
            {
              project_id,
              screenshot_id,
              include_wcag: include_wcag !== false,
            }
          );

          if (!result.success) {
            return {
              content: [{
                type: "text" as const,
                text: `## Visual Analysis Failed\n\n**Error:** ${result.error || "Unknown error"}\n**Screenshot ID:** \`${screenshot_id}\``,
              }],
              isError: true,
            };
          }

          let output = `## Visual Analysis Results\n\n`;
          output += `**Screenshot ID:** \`${result.screenshot_id}\`\n`;
          output += `**Analysis Time:** ${result.analysis_time_ms}ms\n\n`;

          // Visual Elements
          if (result.analysis.visual_elements && result.analysis.visual_elements.length > 0) {
            output += `### Visual Elements Detected (${result.analysis.visual_elements.length})\n\n`;
            output += `| Type | Description | Confidence |\n|------|-------------|------------|\n`;

            result.analysis.visual_elements.slice(0, 15).forEach((element) => {
              const confEmoji = element.confidence > 0.9 ? "🟢" : element.confidence > 0.7 ? "🟡" : "🔴";
              output += `| ${element.type} | ${element.description} | ${confEmoji} ${(element.confidence * 100).toFixed(0)}% |\n`;
            });

            if (result.analysis.visual_elements.length > 15) {
              output += `\n_...and ${result.analysis.visual_elements.length - 15} more elements_\n`;
            }
            output += `\n`;
          }

          // Layout Assessment
          if (result.analysis.layout_assessment) {
            output += `### Layout Assessment\n\n`;
            output += `- **Structure:** ${result.analysis.layout_assessment.structure}\n`;
            output += `- **Responsiveness:** ${result.analysis.layout_assessment.responsiveness}\n`;
            output += `- **Visual Hierarchy:** ${result.analysis.layout_assessment.visual_hierarchy}\n\n`;
          }

          // Color Analysis
          if (result.analysis.color_analysis) {
            output += `### Color Analysis\n\n`;
            output += `- **Color Scheme:** ${result.analysis.color_analysis.color_scheme}\n`;
            if (result.analysis.color_analysis.dominant_colors && result.analysis.color_analysis.dominant_colors.length > 0) {
              output += `- **Dominant Colors:** ${result.analysis.color_analysis.dominant_colors.join(", ")}\n`;
            }
            if (result.analysis.color_analysis.contrast_ratio) {
              const contrastOk = result.analysis.color_analysis.contrast_ratio >= 4.5;
              output += `- **Contrast Ratio:** ${result.analysis.color_analysis.contrast_ratio.toFixed(1)}:1 ${contrastOk ? "pass" : "warning"}\n`;
            }
            output += `\n`;
          }

          // WCAG Compliance
          if (result.wcag_compliance) {
            const wcag = result.wcag_compliance;
            const levelEmoji = wcag.level === "AAA" ? "gold" : wcag.level === "AA" ? "silver" : "bronze";
            const scoreEmoji = wcag.score > 80 ? "🟢" : wcag.score > 60 ? "🟡" : "🔴";

            output += `### WCAG Accessibility Compliance\n\n`;
            output += `**Level:** ${levelEmoji} ${wcag.level}\n`;
            output += `**Score:** ${scoreEmoji} ${wcag.score}/100\n\n`;

            output += `| Metric | Count |\n|--------|-------|\n`;
            output += `| Passed Criteria | ${wcag.passed_criteria} |\n`;
            output += `| Failed Criteria | ${wcag.failed_criteria} |\n`;
            output += `| Warnings | ${wcag.warnings} |\n\n`;

            if (wcag.issues && wcag.issues.length > 0) {
              output += `**Issues Found:**\n\n`;

              wcag.issues.slice(0, 10).forEach((issue, i) => {
                const sevEmoji = issue.severity === "critical" ? "🔴" : issue.severity === "serious" ? "🟠" : issue.severity === "moderate" ? "🟡" : "🟢";
                output += `${i + 1}. ${sevEmoji} **${issue.rule}** (${issue.severity})\n`;
                output += `   - ${issue.description}\n`;
                if (issue.element) output += `   - Element: \`${issue.element}\`\n`;
                output += `   - **Fix:** ${issue.recommendation}\n\n`;
              });

              if (wcag.issues.length > 10) {
                output += `_...and ${wcag.issues.length - 10} more issues_\n\n`;
              }
            }
          }

          // Recommendations
          if (result.recommendations && result.recommendations.length > 0) {
            output += `### Recommendations\n\n`;
            result.recommendations.forEach((rec, i) => {
              output += `${i + 1}. ${rec}\n`;
            });
            output += `\n`;
          }

          output += `---\n**Actions:**\n`;
          output += `- Use \`argus_visual_baseline\` to save this as a baseline\n`;
          output += `- Use \`argus_visual_compare\` to compare with another screenshot`;

          return {
            content: [{ type: "text" as const, text: output }],
          };
        } catch (error) {
          return this.handleError(error);
        }
      }
    );

    // =========================================================================
    // P1 NEW TOOLS: Test CRUD, Test Runs, Reports, Projects, Flaky Tests,
    // Integrations, Failure Patterns, Healing Extensions, Schedule Completion
    // =========================================================================

    // Tool: argus_test_list - List tests for a project
    this.server.tool(
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
          await this.requireAuth();
          const params = new URLSearchParams({ project_id });
          if (status && status !== "all") params.append("status", status);
          if (type) params.append("type", type);
          if (search) params.append("search", search);
          if (limit) params.append("limit", String(limit));
          if (offset) params.append("offset", String(offset));

          const result = await this.callBrainAPIWithAuth<{ tests: Array<{ id: string; name: string; status: string; type: string; created_at: string; last_run_at?: string }>; total: number }>(
            `/api/v1/tests?${params.toString()}`,
            "GET"
          );

          let output = `## Tests (${result.total} total)\n\n`;
          output += `| # | Name | Status | Type | Last Run |\n|---|------|--------|------|----------|\n`;
          (result.tests || []).forEach((t, i) => {
            output += `| ${i + 1} | ${t.name} | ${t.status} | ${t.type || "-"} | ${t.last_run_at ? new Date(t.last_run_at).toLocaleDateString() : "Never"} |\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_test_get - Get a single test by ID
    this.server.tool(
      "argus_test_get",
      "Get full details of a specific test including steps, assertions, and run history.",
      {
        test_id: z.string().describe("The test UUID"),
      },
      async ({ test_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ id: string; name: string; description?: string; steps: unknown[]; status: string; type: string; created_at: string; updated_at: string; tags?: string[] }>(
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
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_test_create - Create a new test
    this.server.tool(
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
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ id: string; name: string; status: string }>(
            `/api/v1/tests`,
            "POST",
            { project_id, name, description, type, steps, tags }
          );

          return {
            content: [{ type: "text" as const, text: `## Test Created\n\n**ID:** \`${result.id}\`\n**Name:** ${result.name}\n**Status:** ${result.status}\n\n**Next:** Use \`argus_test_run_create\` to execute this test.` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_test_update - Update an existing test
    this.server.tool(
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
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ id: string; name: string; status: string; updated_at: string }>(
            `/api/v1/tests/${test_id}`,
            "PUT",
            updates
          );

          return {
            content: [{ type: "text" as const, text: `## Test Updated\n\n**ID:** \`${result.id}\`\n**Name:** ${result.name}\n**Status:** ${result.status}\n**Updated:** ${new Date(result.updated_at).toLocaleString()}` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_test_delete - Delete a test
    this.server.tool(
      "argus_test_delete",
      "Permanently delete a test case. This cannot be undone.",
      {
        test_id: z.string().describe("The test UUID to delete"),
      },
      async ({ test_id }) => {
        try {
          await this.requireAuth();
          await this.callBrainAPIWithAuth<{ success: boolean }>(
            `/api/v1/tests/${test_id}`,
            "DELETE"
          );

          return {
            content: [{ type: "text" as const, text: `## Test Deleted\n\nTest \`${test_id}\` has been permanently deleted.` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_test_run_list - List test runs
    this.server.tool(
      "argus_test_run_list",
      "List test runs for a project, optionally filtered by status or date range.",
      {
        project_id: z.string().describe("The project UUID"),
        status: z.string().optional().describe("Filter by run status (passed, failed, running, pending)"),
        limit: z.number().optional().describe("Max results (default 20)"),
      },
      async ({ project_id, status, limit }) => {
        try {
          await this.requireAuth();
          const params = new URLSearchParams({ project_id });
          if (status) params.append("status", status);
          if (limit) params.append("limit", String(limit));

          const result = await this.callBrainAPIWithAuth<{ runs: Array<{ id: string; status: string; total_tests: number; passed: number; failed: number; started_at: string; duration_ms?: number }>; total: number }>(
            `/api/v1/test-runs?${params.toString()}`,
            "GET"
          );

          let output = `## Test Runs (${result.total} total)\n\n`;
          output += `| # | ID | Status | Tests | Passed | Failed | Duration |\n|---|-----|--------|-------|--------|--------|----------|\n`;
          (result.runs || []).forEach((r, i) => {
            const dur = r.duration_ms ? `${(r.duration_ms / 1000).toFixed(1)}s` : "-";
            const emoji = r.status === "passed" ? "✅" : r.status === "failed" ? "❌" : r.status === "running" ? "🔄" : "⏳";
            output += `| ${i + 1} | \`${r.id.slice(0, 8)}\` | ${emoji} ${r.status} | ${r.total_tests} | ${r.passed} | ${r.failed} | ${dur} |\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_test_run_get - Get test run details
    this.server.tool(
      "argus_test_run_get",
      "Get full details of a specific test run including individual test results.",
      {
        run_id: z.string().describe("The test run UUID"),
      },
      async ({ run_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ id: string; status: string; total_tests: number; passed: number; failed: number; skipped: number; started_at: string; completed_at?: string; duration_ms?: number; environment?: string }>(
            `/api/v1/test-runs/${run_id}`,
            "GET"
          );

          let output = `## Test Run: \`${result.id}\`\n\n`;
          output += `| Metric | Value |\n|--------|-------|\n`;
          output += `| **Status** | ${result.status} |\n`;
          output += `| **Total Tests** | ${result.total_tests} |\n`;
          output += `| **Passed** | ✅ ${result.passed} |\n`;
          output += `| **Failed** | ❌ ${result.failed} |\n`;
          if (result.skipped) output += `| **Skipped** | ⏭️ ${result.skipped} |\n`;
          output += `| **Started** | ${new Date(result.started_at).toLocaleString()} |\n`;
          if (result.completed_at) output += `| **Completed** | ${new Date(result.completed_at).toLocaleString()} |\n`;
          if (result.duration_ms) output += `| **Duration** | ${(result.duration_ms / 1000).toFixed(1)}s |\n`;
          if (result.environment) output += `| **Environment** | ${result.environment} |\n`;

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_test_run_create - Start a new test run
    this.server.tool(
      "argus_test_run_create",
      "Start a new test run to execute one or more tests.",
      {
        project_id: z.string().describe("The project UUID"),
        test_ids: z.array(z.string()).optional().describe("Specific test IDs to run (all if omitted)"),
        environment: z.string().optional().describe("Target environment (e.g., 'staging', 'production')"),
        app_url: z.string().optional().describe("Application URL to test against"),
      },
      async ({ project_id, test_ids, environment, app_url }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ id: string; status: string; total_tests: number }>(
            `/api/v1/test-runs`,
            "POST",
            { project_id, test_ids, environment, app_url }
          );

          return {
            content: [{ type: "text" as const, text: `## Test Run Started\n\n**Run ID:** \`${result.id}\`\n**Status:** ${result.status}\n**Tests:** ${result.total_tests}\n\n**Next:** Use \`argus_test_run_get("${result.id}")\` to check progress.` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_test_run_results - Get results for a test run
    this.server.tool(
      "argus_test_run_results",
      "Get detailed results for each test in a run, including errors and screenshots.",
      {
        run_id: z.string().describe("The test run UUID"),
      },
      async ({ run_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ results: Array<{ test_id: string; test_name: string; status: string; duration_ms?: number; error_message?: string; screenshots?: string[] }> }>(
            `/api/v1/test-runs/${run_id}/results`,
            "GET"
          );

          let output = `## Test Run Results\n\n`;
          (result.results || []).forEach((r, i) => {
            const emoji = r.status === "passed" ? "✅" : r.status === "failed" ? "❌" : "⏭️";
            output += `### ${i + 1}. ${emoji} ${r.test_name}\n`;
            output += `- **Status:** ${r.status}\n`;
            if (r.duration_ms) output += `- **Duration:** ${(r.duration_ms / 1000).toFixed(1)}s\n`;
            if (r.error_message) output += `- **Error:** \`${r.error_message}\`\n`;
            output += `\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_report_generate - Generate a test report
    this.server.tool(
      "argus_report_generate",
      "Generate a comprehensive test report for a project or specific test run.",
      {
        project_id: z.string().describe("The project UUID"),
        run_id: z.string().optional().describe("Specific test run ID (latest if omitted)"),
        format: z.enum(["html", "pdf", "json", "markdown"]).optional().describe("Report format (default: markdown)"),
        include_screenshots: z.boolean().optional().describe("Include screenshots in report"),
      },
      async ({ project_id, run_id, format, include_screenshots }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ id: string; status: string; format: string; url?: string; summary?: string }>(
            `/api/v1/reports/generate`,
            "POST",
            { project_id, run_id, format: format || "markdown", include_screenshots }
          );

          let output = `## Report Generated\n\n`;
          output += `**Report ID:** \`${result.id}\`\n`;
          output += `**Format:** ${result.format}\n`;
          output += `**Status:** ${result.status}\n`;
          if (result.url) output += `**Download:** ${result.url}\n`;
          if (result.summary) output += `\n### Summary\n${result.summary}\n`;

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_report_list - List reports
    this.server.tool(
      "argus_report_list",
      "List generated reports for a project.",
      {
        project_id: z.string().describe("The project UUID"),
        limit: z.number().optional().describe("Max results"),
      },
      async ({ project_id, limit }) => {
        try {
          await this.requireAuth();
          const params = new URLSearchParams({ project_id });
          if (limit) params.append("limit", String(limit));

          const result = await this.callBrainAPIWithAuth<{ reports: Array<{ id: string; format: string; created_at: string; status: string }> }>(
            `/api/v1/reports?${params.toString()}`,
            "GET"
          );

          let output = `## Reports\n\n`;
          output += `| # | ID | Format | Status | Created |\n|---|-----|--------|--------|----------|\n`;
          (result.reports || []).forEach((r, i) => {
            output += `| ${i + 1} | \`${r.id.slice(0, 8)}\` | ${r.format} | ${r.status} | ${new Date(r.created_at).toLocaleDateString()} |\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_report_get - Get report details
    this.server.tool(
      "argus_report_get",
      "Get full details and content of a specific report.",
      {
        report_id: z.string().describe("The report UUID"),
      },
      async ({ report_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ id: string; format: string; content?: string; url?: string; status: string; created_at: string }>(
            `/api/v1/reports/${report_id}`,
            "GET"
          );

          let output = `## Report: \`${result.id}\`\n\n`;
          output += `**Format:** ${result.format} | **Status:** ${result.status} | **Created:** ${new Date(result.created_at).toLocaleString()}\n\n`;
          if (result.content) output += result.content;
          if (result.url) output += `\n**Download:** ${result.url}\n`;

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_report_download - Download a report
    this.server.tool(
      "argus_report_download",
      "Get a download URL for a report file.",
      {
        report_id: z.string().describe("The report UUID"),
      },
      async ({ report_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ url: string; format: string; expires_at?: string }>(
            `/api/v1/reports/${report_id}/download`,
            "GET"
          );

          return {
            content: [{ type: "text" as const, text: `## Report Download\n\n**URL:** ${result.url}\n**Format:** ${result.format}\n${result.expires_at ? `**Expires:** ${new Date(result.expires_at).toLocaleString()}` : ""}` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_project_create - Create a new project
    this.server.tool(
      "argus_project_create",
      "Create a new Skopaq project to organize tests, events, and quality tracking.",
      {
        name: z.string().describe("Project name"),
        description: z.string().optional().describe("Project description"),
        repository_url: z.string().optional().describe("Git repository URL (enables code-aware features)"),
        app_url: z.string().optional().describe("Application URL for testing"),
      },
      async ({ name, description, repository_url, app_url }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ id: string; name: string; created_at: string }>(
            `/api/v1/projects`,
            "POST",
            { name, description, repository_url, app_url }
          );

          return {
            content: [{ type: "text" as const, text: `## Project Created\n\n**ID:** \`${result.id}\`\n**Name:** ${result.name}\n**Created:** ${new Date(result.created_at).toLocaleString()}\n\n**Next:** Set up integrations with \`argus_integrations_connect\` or start testing with \`argus_test_create\`.` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_project_get - Get project details
    this.server.tool(
      "argus_project_get",
      "Get full details of a project including settings, integrations, and configuration.",
      {
        project_id: z.string().describe("The project UUID"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ id: string; name: string; description?: string; repository_url?: string; app_url?: string; created_at: string; settings?: Record<string, unknown> }>(
            `/api/v1/projects/${project_id}`,
            "GET"
          );

          let output = `## Project: ${result.name}\n\n`;
          output += `| Field | Value |\n|-------|-------|\n`;
          output += `| **ID** | \`${result.id}\` |\n`;
          if (result.description) output += `| **Description** | ${result.description} |\n`;
          if (result.repository_url) output += `| **Repository** | ${result.repository_url} |\n`;
          if (result.app_url) output += `| **App URL** | ${result.app_url} |\n`;
          output += `| **Created** | ${new Date(result.created_at).toLocaleString()} |\n`;

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_project_update - Update a project
    this.server.tool(
      "argus_project_update",
      "Update project settings, name, description, or configuration.",
      {
        project_id: z.string().describe("The project UUID"),
        name: z.string().optional().describe("New name"),
        description: z.string().optional().describe("New description"),
        repository_url: z.string().optional().describe("Git repository URL"),
        app_url: z.string().optional().describe("Application URL"),
      },
      async ({ project_id, ...updates }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ id: string; name: string; updated_at: string }>(
            `/api/v1/projects/${project_id}`,
            "PUT",
            updates
          );

          return {
            content: [{ type: "text" as const, text: `## Project Updated\n\n**ID:** \`${result.id}\`\n**Name:** ${result.name}\n**Updated:** ${new Date(result.updated_at).toLocaleString()}` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_flaky_tests - List flaky tests
    this.server.tool(
      "argus_flaky_tests",
      "List tests that have been detected as flaky (intermittent failures) with confidence scores.",
      {
        project_id: z.string().describe("The project UUID"),
        min_flakiness: z.number().optional().describe("Minimum flakiness score (0-1, default 0.1)"),
        limit: z.number().optional().describe("Max results"),
      },
      async ({ project_id, min_flakiness, limit }) => {
        try {
          await this.requireAuth();
          const params = new URLSearchParams({ project_id });
          if (min_flakiness !== undefined) params.append("min_flakiness", String(min_flakiness));
          if (limit) params.append("limit", String(limit));

          const result = await this.callBrainAPIWithAuth<FlakyTestsResponse>(
            `/api/v1/flaky-tests?${params.toString()}`,
            "GET"
          );

          let output = `## Flaky Tests\n\n`;
          output += `| # | Test Name | Flakiness | Pass Rate | Total Runs |\n|---|-----------|-----------|-----------|------------|\n`;
          (result.flaky_tests || []).forEach((t, i) => {
            const emoji = t.flakiness_score > 0.5 ? "🔴" : t.flakiness_score > 0.2 ? "🟡" : "🟢";
            output += `| ${i + 1} | ${t.test_name} | ${emoji} ${(t.flakiness_score * 100).toFixed(0)}% | ${(t.pass_rate * 100).toFixed(0)}% | ${t.total_runs} |\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_flaky_trend - Get flaky test trend over time
    this.server.tool(
      "argus_flaky_trend",
      "Get trend data showing how test flakiness has changed over time.",
      {
        project_id: z.string().describe("The project UUID"),
        days: z.number().optional().describe("Number of days to look back (default 30)"),
      },
      async ({ project_id, days }) => {
        try {
          await this.requireAuth();
          const params = new URLSearchParams({ project_id });
          if (days) params.append("days", String(days));

          const result = await this.callBrainAPIWithAuth<{ trend: Array<{ date: string; flaky_count: number; total_tests: number; flakiness_rate: number }> }>(
            `/api/v1/flaky-tests/trend?${params.toString()}`,
            "GET"
          );

          let output = `## Flaky Test Trend (${days || 30} days)\n\n`;
          output += `| Date | Flaky Count | Total | Rate |\n|------|-------------|-------|------|\n`;
          (result.trend || []).forEach(t => {
            output += `| ${t.date} | ${t.flaky_count} | ${t.total_tests} | ${(t.flakiness_rate * 100).toFixed(1)}% |\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_flaky_quarantine - Quarantine a flaky test
    this.server.tool(
      "argus_flaky_quarantine",
      "Quarantine a flaky test to stop it from blocking CI pipelines while it's being fixed.",
      {
        test_id: z.string().describe("The flaky test UUID to quarantine"),
        reason: z.string().optional().describe("Reason for quarantining"),
      },
      async ({ test_id, reason }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ id: string; quarantined: boolean; quarantined_at: string }>(
            `/api/v1/flaky-tests/${test_id}/quarantine`,
            "POST",
            { reason }
          );

          return {
            content: [{ type: "text" as const, text: `## Test Quarantined\n\n**Test ID:** \`${result.id}\`\n**Quarantined:** ${result.quarantined ? "Yes" : "No"}\n**Since:** ${new Date(result.quarantined_at).toLocaleString()}\n${reason ? `**Reason:** ${reason}` : ""}\n\nThe test will be excluded from CI/CD gate decisions until un-quarantined.` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_integrations_list - List connected integrations
    this.server.tool(
      "argus_integrations_list",
      "List all connected integrations (Sentry, GitHub, Jira, Datadog, etc.) and their sync status.",
      {
        project_id: z.string().optional().describe("Filter by project UUID"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const params = project_id ? `?project_id=${project_id}` : "";

          const result = await this.callBrainAPIWithAuth<{ integrations: Array<{ id: string; platform: string; status: string; last_sync?: string; project_id?: string }> }>(
            `/api/v1/integrations${params}`,
            "GET"
          );

          let output = `## Connected Integrations\n\n`;
          output += `| # | Platform | Status | Last Sync | Project |\n|---|----------|--------|-----------|----------|\n`;
          (result.integrations || []).forEach((intg, i) => {
            const statusEmoji = intg.status === "active" ? "🟢" : intg.status === "error" ? "🔴" : "🟡";
            output += `| ${i + 1} | ${intg.platform} | ${statusEmoji} ${intg.status} | ${intg.last_sync ? new Date(intg.last_sync).toLocaleDateString() : "Never"} | ${intg.project_id ? `\`${intg.project_id.slice(0, 8)}\`` : "-"} |\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_integrations_connect - Connect a new integration
    this.server.tool(
      "argus_integrations_connect",
      "Connect a new integration platform (Sentry, GitHub, Jira, Datadog, PagerDuty, etc.).",
      {
        platform: z.string().describe("Integration platform (e.g., 'sentry', 'github', 'jira', 'datadog')"),
        project_id: z.string().describe("Project UUID to connect to"),
        credentials: z.record(z.string()).describe("Platform-specific credentials (e.g., {api_key, org_slug})"),
        config: z.record(z.unknown()).optional().describe("Additional configuration"),
      },
      async ({ platform, project_id, credentials, config }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ id: string; platform: string; status: string }>(
            `/api/v1/integrations/connect`,
            "POST",
            { platform, project_id, credentials, config }
          );

          return {
            content: [{ type: "text" as const, text: `## Integration Connected\n\n**ID:** \`${result.id}\`\n**Platform:** ${result.platform}\n**Status:** ${result.status}\n\n**Next:** Use \`argus_integrations_sync\` to trigger initial data sync.` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_integrations_disconnect - Disconnect an integration
    this.server.tool(
      "argus_integrations_disconnect",
      "Disconnect an integration and stop syncing data from it.",
      {
        integration_id: z.string().describe("The integration UUID to disconnect"),
      },
      async ({ integration_id }) => {
        try {
          await this.requireAuth();
          await this.callBrainAPIWithAuth<{ success: boolean }>(
            `/api/v1/integrations/${integration_id}/disconnect`,
            "POST"
          );

          return {
            content: [{ type: "text" as const, text: `## Integration Disconnected\n\nIntegration \`${integration_id}\` has been disconnected. No further data will be synced from this source.` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_integrations_sync - Trigger integration sync
    this.server.tool(
      "argus_integrations_sync",
      "Manually trigger a data sync from a connected integration.",
      {
        integration_id: z.string().describe("The integration UUID to sync"),
      },
      async ({ integration_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ status: string; events_synced?: number; last_sync: string }>(
            `/api/v1/integrations/${integration_id}/trigger-sync`,
            "POST"
          );

          return {
            content: [{ type: "text" as const, text: `## Sync Triggered\n\n**Status:** ${result.status}\n${result.events_synced !== undefined ? `**Events Synced:** ${result.events_synced}\n` : ""}**Last Sync:** ${new Date(result.last_sync).toLocaleString()}` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_failure_patterns - List learned failure patterns
    this.server.tool(
      "argus_failure_patterns",
      "List all learned failure patterns including selector changes, API changes, and timing issues.",
      {
        project_id: z.string().optional().describe("Filter by project UUID"),
        pattern_type: z.string().optional().describe("Filter by pattern type (e.g., 'selector_changed', 'api_changed', 'timing')"),
        limit: z.number().optional().describe("Max results"),
      },
      async ({ project_id, pattern_type, limit }) => {
        try {
          await this.requireAuth();
          const params = new URLSearchParams();
          if (project_id) params.append("project_id", project_id);
          if (pattern_type) params.append("pattern_type", pattern_type);
          if (limit) params.append("limit", String(limit));

          const result = await this.callBrainAPIWithAuth<{ patterns: Array<{ id: string; pattern_type: string; description: string; occurrences: number; confidence: number; last_seen: string }> }>(
            `/api/v1/patterns?${params.toString()}`,
            "GET"
          );

          let output = `## Failure Patterns\n\n`;
          output += `| # | Type | Description | Occurrences | Confidence | Last Seen |\n|---|------|-------------|-------------|------------|------------|\n`;
          (result.patterns || []).forEach((p, i) => {
            output += `| ${i + 1} | ${p.pattern_type} | ${p.description.slice(0, 60)} | ${p.occurrences} | ${(p.confidence * 100).toFixed(0)}% | ${new Date(p.last_seen).toLocaleDateString()} |\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_failure_predict - Predict potential failures
    this.server.tool(
      "argus_failure_predict",
      "Use AI to predict which tests are likely to fail based on code changes and historical patterns.",
      {
        project_id: z.string().describe("The project UUID"),
        changed_files: z.array(z.string()).optional().describe("List of changed file paths"),
        commit_sha: z.string().optional().describe("Git commit SHA to analyze"),
      },
      async ({ project_id, changed_files, commit_sha }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ predictions: Array<{ test_name: string; failure_probability: number; reason: string; pattern_id?: string }> }>(
            `/api/v1/patterns/predict`,
            "POST",
            { project_id, changed_files, commit_sha }
          );

          let output = `## Failure Predictions\n\n`;
          (result.predictions || []).forEach((p, i) => {
            const emoji = p.failure_probability > 0.7 ? "🔴" : p.failure_probability > 0.4 ? "🟡" : "🟢";
            output += `${i + 1}. ${emoji} **${p.test_name}** — ${(p.failure_probability * 100).toFixed(0)}% failure probability\n`;
            output += `   Reason: ${p.reason}\n\n`;
          });

          if (!result.predictions?.length) {
            output += "No significant failure predictions for these changes.\n";
          }

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_failure_train - Train failure pattern model
    this.server.tool(
      "argus_failure_train",
      "Manually trigger retraining of the failure pattern model with latest data.",
      {
        project_id: z.string().describe("The project UUID"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ status: string; patterns_learned: number; training_duration_ms?: number }>(
            `/api/v1/patterns/train`,
            "POST",
            { project_id }
          );

          return {
            content: [{ type: "text" as const, text: `## Pattern Training Complete\n\n**Status:** ${result.status}\n**Patterns Learned:** ${result.patterns_learned}\n${result.training_duration_ms ? `**Duration:** ${(result.training_duration_ms / 1000).toFixed(1)}s` : ""}` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_healing_suggest - Get healing suggestions for a failure
    this.server.tool(
      "argus_healing_suggest",
      "Get AI-powered fix suggestions for a test failure without auto-applying them.",
      {
        org_id: z.string().describe("The organization UUID"),
        failure_id: z.string().describe("The failure UUID to get suggestions for"),
        test_id: z.string().optional().describe("The test UUID for additional context"),
      },
      async ({ org_id, failure_id, test_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ suggestions: Array<{ type: string; description: string; confidence: number; fix: Record<string, unknown>; source: string }> }>(
            `/api/v1/healing/${org_id}/suggest`,
            "POST",
            { failure_id, test_id }
          );

          let output = `## Healing Suggestions\n\n`;
          (result.suggestions || []).forEach((s, i) => {
            const emoji = s.confidence > 0.8 ? "🟢" : s.confidence > 0.5 ? "🟡" : "🔴";
            output += `### ${i + 1}. ${s.type} (${emoji} ${(s.confidence * 100).toFixed(0)}% confidence)\n`;
            output += `**Source:** ${s.source}\n`;
            output += `**Description:** ${s.description}\n\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_healing_root_cause - Analyze root cause of a failure
    this.server.tool(
      "argus_healing_root_cause",
      "Use AI to analyze the root cause of a test failure by examining code changes, DOM diffs, and historical patterns.",
      {
        org_id: z.string().describe("The organization UUID"),
        failure_id: z.string().describe("The failure UUID to analyze"),
      },
      async ({ org_id, failure_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ root_cause: string; confidence: number; contributing_factors: string[]; recommended_fix: string; related_patterns: Array<{ id: string; description: string }> }>(
            `/api/v1/healing/${org_id}/analyze-root-cause`,
            "POST",
            { failure_id }
          );

          let output = `## Root Cause Analysis\n\n`;
          output += `**Root Cause:** ${result.root_cause}\n`;
          output += `**Confidence:** ${(result.confidence * 100).toFixed(0)}%\n\n`;
          if (result.contributing_factors?.length) {
            output += `**Contributing Factors:**\n`;
            result.contributing_factors.forEach(f => { output += `- ${f}\n`; });
            output += `\n`;
          }
          output += `**Recommended Fix:** ${result.recommended_fix}\n`;
          if (result.related_patterns?.length) {
            output += `\n**Related Patterns:**\n`;
            result.related_patterns.forEach(p => { output += `- \`${p.id}\`: ${p.description}\n`; });
          }

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_healing_similar_errors - Find similar past errors
    this.server.tool(
      "argus_healing_similar_errors",
      "Search for similar past errors using semantic search on the Cognee knowledge graph.",
      {
        org_id: z.string().describe("The organization UUID"),
        error_message: z.string().describe("The error message to search for"),
        error_type: z.string().optional().describe("Error type for filtering"),
        limit: z.number().optional().describe("Max results (default 5)"),
      },
      async ({ org_id, error_message, error_type, limit }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ similar_errors: Array<{ error_message: string; error_type: string; similarity: number; resolution?: string; test_name?: string; occurred_at: string }> }>(
            `/api/v1/healing/${org_id}/similar-errors`,
            "POST",
            { error_message, error_type, limit: limit || 5 }
          );

          let output = `## Similar Past Errors\n\n`;
          (result.similar_errors || []).forEach((e, i) => {
            output += `### ${i + 1}. ${(e.similarity * 100).toFixed(0)}% match\n`;
            output += `**Error:** \`${e.error_message.slice(0, 100)}\`\n`;
            output += `**Type:** ${e.error_type}\n`;
            if (e.test_name) output += `**Test:** ${e.test_name}\n`;
            output += `**When:** ${new Date(e.occurred_at).toLocaleDateString()}\n`;
            if (e.resolution) output += `**Resolution:** ${e.resolution}\n`;
            output += `\n`;
          });

          if (!result.similar_errors?.length) {
            output += "No similar errors found in the knowledge graph.\n";
          }

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_schedule_get - Get schedule details
    this.server.tool(
      "argus_schedule_get",
      "Get full details of a test schedule including cron expression, tests, and configuration.",
      {
        schedule_id: z.string().describe("The schedule UUID"),
      },
      async ({ schedule_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ id: string; name: string; cron: string; enabled: boolean; project_id: string; test_ids?: string[]; environment?: string; created_at: string; next_run_at?: string }>(
            `/api/v1/schedules/${schedule_id}`,
            "GET"
          );

          let output = `## Schedule: ${result.name}\n\n`;
          output += `| Field | Value |\n|-------|-------|\n`;
          output += `| **ID** | \`${result.id}\` |\n`;
          output += `| **Cron** | \`${result.cron}\` |\n`;
          output += `| **Enabled** | ${result.enabled ? "Yes ✅" : "No ❌"} |\n`;
          output += `| **Project** | \`${result.project_id}\` |\n`;
          if (result.test_ids?.length) output += `| **Tests** | ${result.test_ids.length} test(s) |\n`;
          if (result.environment) output += `| **Environment** | ${result.environment} |\n`;
          output += `| **Created** | ${new Date(result.created_at).toLocaleString()} |\n`;
          if (result.next_run_at) output += `| **Next Run** | ${new Date(result.next_run_at).toLocaleString()} |\n`;

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_schedule_update - Update a schedule
    this.server.tool(
      "argus_schedule_update",
      "Update a test schedule's cron expression, name, enabled status, or test configuration.",
      {
        schedule_id: z.string().describe("The schedule UUID"),
        name: z.string().optional().describe("New schedule name"),
        cron: z.string().optional().describe("New cron expression"),
        enabled: z.boolean().optional().describe("Enable/disable the schedule"),
        test_ids: z.array(z.string()).optional().describe("Updated list of test IDs to run"),
        environment: z.string().optional().describe("Target environment"),
      },
      async ({ schedule_id, ...updates }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ id: string; name: string; cron: string; enabled: boolean; updated_at: string }>(
            `/api/v1/schedules/${schedule_id}`,
            "PUT",
            updates
          );

          return {
            content: [{ type: "text" as const, text: `## Schedule Updated\n\n**ID:** \`${result.id}\`\n**Name:** ${result.name}\n**Cron:** \`${result.cron}\`\n**Enabled:** ${result.enabled ? "Yes ✅" : "No ❌"}\n**Updated:** ${new Date(result.updated_at).toLocaleString()}` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_schedule_delete - Delete a schedule
    this.server.tool(
      "argus_schedule_delete",
      "Permanently delete a test schedule. This stops all future runs.",
      {
        schedule_id: z.string().describe("The schedule UUID to delete"),
      },
      async ({ schedule_id }) => {
        try {
          await this.requireAuth();
          await this.callBrainAPIWithAuth<{ success: boolean }>(
            `/api/v1/schedules/${schedule_id}`,
            "DELETE"
          );

          return {
            content: [{ type: "text" as const, text: `## Schedule Deleted\n\nSchedule \`${schedule_id}\` has been permanently deleted. No further test runs will be triggered by this schedule.` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // =========================================================================
    // END P1 NEW TOOLS
    // =========================================================================

    // =========================================================================
    // P2 TOOLS: Accessibility, Performance, SLO, Impact Graph, Chat,
    // Parameterized, Insights, SAST
    // =========================================================================

    // Tool: argus_accessibility_audit - Run accessibility audit
    this.server.tool(
      "argus_accessibility_audit",
      "Run a WCAG 2.1 accessibility audit on a URL, identifying violations, warnings, and best practice recommendations.",
      {
        project_id: z.string().describe("The project UUID"),
        url: z.string().describe("URL to audit"),
        standard: z.enum(["WCAG2A", "WCAG2AA", "WCAG2AAA"]).optional().describe("WCAG standard level (default: WCAG2AA)"),
      },
      async ({ project_id, url, standard }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ score: number; violations: Array<{ rule: string; impact: string; description: string; nodes: number }>; passes: number; total_rules: number }>(
            `/api/v1/accessibility/audit`,
            "POST",
            { project_id, url, standard: standard || "WCAG2AA" }
          );

          let output = `## Accessibility Audit\n\n**Score:** ${result.score}/100 | **Standard:** ${standard || "WCAG2AA"}\n**Passed:** ${result.passes}/${result.total_rules} rules\n\n`;
          if (result.violations?.length) {
            output += `### Violations (${result.violations.length})\n\n`;
            output += `| # | Rule | Impact | Description | Nodes |\n|---|------|--------|-------------|-------|\n`;
            result.violations.forEach((v, i) => {
              const emoji = v.impact === "critical" ? "🔴" : v.impact === "serious" ? "🟠" : "🟡";
              output += `| ${i + 1} | ${v.rule} | ${emoji} ${v.impact} | ${v.description.slice(0, 60)} | ${v.nodes} |\n`;
            });
          }

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_accessibility_issues - List accessibility issues
    this.server.tool(
      "argus_accessibility_issues",
      "List open accessibility issues found across audits for a project.",
      {
        project_id: z.string().describe("The project UUID"),
        impact: z.string().optional().describe("Filter by impact level (critical, serious, moderate, minor)"),
      },
      async ({ project_id, impact }) => {
        try {
          await this.requireAuth();
          const params = new URLSearchParams({ project_id });
          if (impact) params.append("impact", impact);

          const result = await this.callBrainAPIWithAuth<{ issues: Array<{ id: string; rule: string; impact: string; url: string; status: string }>; total: number }>(
            `/api/v1/accessibility/issues?${params.toString()}`,
            "GET"
          );

          let output = `## Accessibility Issues (${result.total})\n\n`;
          output += `| # | Rule | Impact | URL | Status |\n|---|------|--------|-----|--------|\n`;
          (result.issues || []).forEach((issue, i) => {
            output += `| ${i + 1} | ${issue.rule} | ${issue.impact} | ${issue.url.slice(0, 40)} | ${issue.status} |\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_performance_tests - Run performance tests
    this.server.tool(
      "argus_performance_tests",
      "Run performance tests to measure page load times, Core Web Vitals, and response times.",
      {
        project_id: z.string().describe("The project UUID"),
        url: z.string().describe("URL to test"),
        iterations: z.number().optional().describe("Number of test iterations (default 3)"),
      },
      async ({ project_id, url, iterations }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ metrics: { lcp_ms: number; fid_ms: number; cls: number; ttfb_ms: number; fcp_ms: number }; grade: string }>(
            `/api/v1/performance/test`,
            "POST",
            { project_id, url, iterations: iterations || 3 }
          );

          const m = result.metrics;
          let output = `## Performance Test: ${url}\n\n**Grade:** ${result.grade}\n\n`;
          output += `| Metric | Value | Status |\n|--------|-------|--------|\n`;
          output += `| LCP (Largest Contentful Paint) | ${m.lcp_ms}ms | ${m.lcp_ms < 2500 ? "🟢 Good" : m.lcp_ms < 4000 ? "🟡 Needs Work" : "🔴 Poor"} |\n`;
          output += `| FID (First Input Delay) | ${m.fid_ms}ms | ${m.fid_ms < 100 ? "🟢 Good" : m.fid_ms < 300 ? "🟡 Needs Work" : "🔴 Poor"} |\n`;
          output += `| CLS (Cumulative Layout Shift) | ${m.cls} | ${m.cls < 0.1 ? "🟢 Good" : m.cls < 0.25 ? "🟡 Needs Work" : "🔴 Poor"} |\n`;
          output += `| TTFB (Time to First Byte) | ${m.ttfb_ms}ms | ${m.ttfb_ms < 800 ? "🟢 Good" : "🟡 Slow"} |\n`;
          output += `| FCP (First Contentful Paint) | ${m.fcp_ms}ms | ${m.fcp_ms < 1800 ? "🟢 Good" : "🟡 Slow"} |\n`;

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_performance_trends - Get performance trends
    this.server.tool(
      "argus_performance_trends",
      "Get performance metric trends over time to identify regressions.",
      {
        project_id: z.string().describe("The project UUID"),
        days: z.number().optional().describe("Days to look back (default 30)"),
        url: z.string().optional().describe("Filter by specific URL"),
      },
      async ({ project_id, days, url }) => {
        try {
          await this.requireAuth();
          const params = new URLSearchParams({ project_id });
          if (days) params.append("days", String(days));
          if (url) params.append("url", url);

          const result = await this.callBrainAPIWithAuth<{ trends: Array<{ date: string; lcp_ms: number; cls: number; ttfb_ms: number }> }>(
            `/api/v1/performance/trends?${params.toString()}`,
            "GET"
          );

          let output = `## Performance Trends\n\n`;
          output += `| Date | LCP (ms) | CLS | TTFB (ms) |\n|------|----------|-----|----------|\n`;
          (result.trends || []).forEach(t => {
            output += `| ${t.date} | ${t.lcp_ms} | ${t.cls.toFixed(3)} | ${t.ttfb_ms} |\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_performance_summary - Get performance summary
    this.server.tool(
      "argus_performance_summary",
      "Get a summary of performance metrics across all monitored URLs in a project.",
      {
        project_id: z.string().describe("The project UUID"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ urls: Array<{ url: string; avg_lcp_ms: number; avg_cls: number; grade: string; tests_run: number }> }>(
            `/api/v1/performance/summary?project_id=${project_id}`,
            "GET"
          );

          let output = `## Performance Summary\n\n`;
          output += `| URL | Avg LCP | Avg CLS | Grade | Tests |\n|-----|---------|---------|-------|-------|\n`;
          (result.urls || []).forEach(u => {
            output += `| ${u.url.slice(0, 50)} | ${u.avg_lcp_ms}ms | ${u.avg_cls.toFixed(3)} | ${u.grade} | ${u.tests_run} |\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_slo_compliance - Check SLO compliance
    this.server.tool(
      "argus_slo_compliance",
      "Check Service Level Objective compliance for test reliability, performance, and availability.",
      {
        project_id: z.string().describe("The project UUID"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ slos: Array<{ name: string; target: number; current: number; compliant: boolean; window: string }> }>(
            `/api/v1/slo/compliance?project_id=${project_id}`,
            "GET"
          );

          let output = `## SLO Compliance\n\n`;
          output += `| SLO | Target | Current | Status | Window |\n|-----|--------|---------|--------|--------|\n`;
          (result.slos || []).forEach(s => {
            const emoji = s.compliant ? "✅" : "❌";
            output += `| ${s.name} | ${(s.target * 100).toFixed(1)}% | ${(s.current * 100).toFixed(1)}% | ${emoji} | ${s.window} |\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_slo_error_budget - Check remaining error budget
    this.server.tool(
      "argus_slo_error_budget",
      "Check remaining error budget for each SLO to know how much room for failures exists.",
      {
        project_id: z.string().describe("The project UUID"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ budgets: Array<{ slo_name: string; budget_total: number; budget_remaining: number; budget_consumed_pct: number; burn_rate: number }> }>(
            `/api/v1/slo/error-budget?project_id=${project_id}`,
            "GET"
          );

          let output = `## Error Budget Status\n\n`;
          output += `| SLO | Budget | Remaining | Consumed | Burn Rate |\n|-----|--------|-----------|----------|----------|\n`;
          (result.budgets || []).forEach(b => {
            const emoji = b.budget_consumed_pct > 80 ? "🔴" : b.budget_consumed_pct > 50 ? "🟡" : "🟢";
            output += `| ${b.slo_name} | ${b.budget_total} | ${b.budget_remaining} | ${emoji} ${b.budget_consumed_pct.toFixed(0)}% | ${b.burn_rate.toFixed(2)}x |\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_slo_critical - Get critical SLO alerts
    this.server.tool(
      "argus_slo_critical",
      "Get SLOs that are at risk of breaching their targets.",
      {
        project_id: z.string().describe("The project UUID"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ alerts: Array<{ slo_name: string; status: string; message: string; time_to_breach?: string }> }>(
            `/api/v1/slo/critical?project_id=${project_id}`,
            "GET"
          );

          let output = `## Critical SLO Alerts\n\n`;
          if (!result.alerts?.length) {
            output += "All SLOs are healthy. No critical alerts.\n";
          } else {
            result.alerts.forEach((a, i) => {
              output += `### ${i + 1}. ${a.slo_name}\n`;
              output += `**Status:** ${a.status}\n**Message:** ${a.message}\n`;
              if (a.time_to_breach) output += `**Time to Breach:** ${a.time_to_breach}\n`;
              output += `\n`;
            });
          }

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_impact_affected - Get affected components from code changes
    this.server.tool(
      "argus_impact_affected",
      "Analyze which components, tests, and user flows are affected by code changes.",
      {
        project_id: z.string().describe("The project UUID"),
        changed_files: z.array(z.string()).describe("List of changed file paths"),
      },
      async ({ project_id, changed_files }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ affected: Array<{ component: string; type: string; impact_level: string; tests: string[] }> }>(
            `/api/v1/impact-graph/affected`,
            "POST",
            { project_id, changed_files }
          );

          let output = `## Impact Analysis\n\n`;
          (result.affected || []).forEach((a, i) => {
            const emoji = a.impact_level === "high" ? "🔴" : a.impact_level === "medium" ? "🟡" : "🟢";
            output += `### ${i + 1}. ${a.component} (${emoji} ${a.impact_level})\n`;
            output += `**Type:** ${a.type}\n`;
            if (a.tests.length) output += `**Affected Tests:** ${a.tests.join(", ")}\n`;
            output += `\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_impact_coverage - Get impact graph coverage
    this.server.tool(
      "argus_impact_coverage",
      "Get test coverage mapped to the dependency graph showing which code paths have test coverage.",
      {
        project_id: z.string().describe("The project UUID"),
      },
      async ({ project_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ coverage_pct: number; nodes: number; covered_nodes: number; uncovered_critical: string[] }>(
            `/api/v1/impact-graph/coverage?project_id=${project_id}`,
            "GET"
          );

          let output = `## Impact Graph Coverage\n\n`;
          output += `**Overall:** ${result.coverage_pct.toFixed(1)}%\n`;
          output += `**Nodes:** ${result.covered_nodes}/${result.nodes} covered\n\n`;
          if (result.uncovered_critical?.length) {
            output += `### Uncovered Critical Paths\n`;
            result.uncovered_critical.forEach(p => { output += `- ${p}\n`; });
          }

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_chat_message - Send chat message to AI assistant
    this.server.tool(
      "argus_chat_message",
      "Send a message to the Skopaq AI chat assistant with full context awareness, tool use, and conversation memory.",
      {
        message: z.string().describe("Your message"),
        thread_id: z.string().optional().describe("Thread ID for conversation continuity"),
        project_id: z.string().optional().describe("Project context"),
      },
      async ({ message, thread_id, project_id }) => {
        try {
          await this.requireAuth();
          let content = message;
          if (project_id) content = `[Project: ${project_id}] ${content}`;

          const result = await this.callBrainAPIWithAuth<{ message: string; thread_id: string; tool_calls?: Array<{ name: string }> }>(
            `/api/v1/chat/message`,
            "POST",
            { messages: [{ role: "user", content }], thread_id }
          );

          let output = result.message;
          if (result.thread_id) output += `\n\n*Thread: \`${result.thread_id}\`*`;

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_chat_history - Get chat history
    this.server.tool(
      "argus_chat_history",
      "Get chat conversation history for a thread.",
      {
        thread_id: z.string().describe("The conversation thread ID"),
      },
      async ({ thread_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ messages: Array<{ role: string; content: string; timestamp: string }> }>(
            `/api/v1/chat/history?thread_id=${thread_id}`,
            "GET"
          );

          let output = `## Chat History (Thread: \`${thread_id}\`)\n\n`;
          (result.messages || []).forEach(m => {
            const icon = m.role === "user" ? "👤" : "🤖";
            output += `${icon} **${m.role}** (${new Date(m.timestamp).toLocaleTimeString()}):\n${m.content.slice(0, 200)}\n\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_chat_threads - List chat threads
    this.server.tool(
      "argus_chat_threads",
      "List all chat conversation threads.",
      {
        limit: z.number().optional().describe("Max results"),
      },
      async ({ limit }) => {
        try {
          await this.requireAuth();
          const params = limit ? `?limit=${limit}` : "";
          const result = await this.callBrainAPIWithAuth<{ threads: Array<{ id: string; title?: string; created_at: string; message_count: number }> }>(
            `/api/v1/chat/threads${params}`,
            "GET"
          );

          let output = `## Chat Threads\n\n`;
          output += `| # | Thread ID | Title | Messages | Created |\n|---|-----------|-------|----------|---------|\n`;
          (result.threads || []).forEach((t, i) => {
            output += `| ${i + 1} | \`${t.id.slice(0, 8)}\` | ${t.title || "-"} | ${t.message_count} | ${new Date(t.created_at).toLocaleDateString()} |\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_param_expand - Expand parameterized test
    this.server.tool(
      "argus_param_expand",
      "Expand a parameterized test template with data combinations to see all generated test variants.",
      {
        project_id: z.string().describe("The project UUID"),
        test_id: z.string().describe("The parameterized test UUID"),
      },
      async ({ project_id, test_id }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ variants: Array<{ name: string; parameters: Record<string, unknown> }> }>(
            `/api/v1/parameterized/expand`,
            "POST",
            { project_id, test_id }
          );

          let output = `## Expanded Variants (${result.variants?.length || 0})\n\n`;
          (result.variants || []).forEach((v, i) => {
            output += `${i + 1}. **${v.name}**: ${JSON.stringify(v.parameters)}\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_param_execute - Execute parameterized tests
    this.server.tool(
      "argus_param_execute",
      "Execute a parameterized test with all data combinations.",
      {
        project_id: z.string().describe("The project UUID"),
        test_id: z.string().describe("The parameterized test UUID"),
        data_source: z.string().optional().describe("Data source ID for test parameters"),
      },
      async ({ project_id, test_id, data_source }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ run_id: string; total_variants: number; status: string }>(
            `/api/v1/parameterized/execute`,
            "POST",
            { project_id, test_id, data_source }
          );

          return {
            content: [{ type: "text" as const, text: `## Parameterized Test Execution\n\n**Run ID:** \`${result.run_id}\`\n**Variants:** ${result.total_variants}\n**Status:** ${result.status}` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_param_import - Import test parameters from CSV/JSON
    this.server.tool(
      "argus_param_import",
      "Import test parameter data from CSV or JSON format for parameterized testing.",
      {
        project_id: z.string().describe("The project UUID"),
        test_id: z.string().describe("The parameterized test UUID"),
        format: z.enum(["csv", "json"]).describe("Data format"),
        data: z.string().describe("The parameter data (CSV or JSON string)"),
      },
      async ({ project_id, test_id, format, data }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ imported: number; data_source_id: string }>(
            `/api/v1/parameterized/import`,
            "POST",
            { project_id, test_id, format, data }
          );

          return {
            content: [{ type: "text" as const, text: `## Parameters Imported\n\n**Imported:** ${result.imported} row(s)\n**Data Source ID:** \`${result.data_source_id}\`` }],
          };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_insights_generate - Generate AI insights
    this.server.tool(
      "argus_insights_generate",
      "Generate AI-powered insights about testing quality, trends, and recommended actions.",
      {
        project_id: z.string().describe("The project UUID"),
        focus: z.string().optional().describe("Focus area (e.g., 'flaky', 'coverage', 'performance', 'security')"),
      },
      async ({ project_id, focus }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ insights: Array<{ title: string; description: string; severity: string; action: string; category: string }> }>(
            `/api/v1/insights/generate`,
            "POST",
            { project_id, focus }
          );

          let output = `## AI Insights\n\n`;
          (result.insights || []).forEach((ins, i) => {
            const emoji = ins.severity === "critical" ? "🔴" : ins.severity === "warning" ? "🟡" : "🟢";
            output += `### ${i + 1}. ${emoji} ${ins.title}\n`;
            output += `**Category:** ${ins.category}\n${ins.description}\n\n**Action:** ${ins.action}\n\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_insights_list - List past insights
    this.server.tool(
      "argus_insights_list",
      "List previously generated insights for a project.",
      {
        project_id: z.string().describe("The project UUID"),
        limit: z.number().optional().describe("Max results"),
      },
      async ({ project_id, limit }) => {
        try {
          await this.requireAuth();
          const params = new URLSearchParams({ project_id });
          if (limit) params.append("limit", String(limit));

          const result = await this.callBrainAPIWithAuth<{ insights: Array<{ id: string; title: string; severity: string; created_at: string; status: string }> }>(
            `/api/v1/insights?${params.toString()}`,
            "GET"
          );

          let output = `## Insights History\n\n`;
          output += `| # | Title | Severity | Status | Date |\n|---|-------|----------|--------|------|\n`;
          (result.insights || []).forEach((ins, i) => {
            output += `| ${i + 1} | ${ins.title.slice(0, 50)} | ${ins.severity} | ${ins.status} | ${new Date(ins.created_at).toLocaleDateString()} |\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_sast_analyze - Run static analysis
    this.server.tool(
      "argus_sast_analyze",
      "Run AI-powered static analysis (SAST) on code to identify security vulnerabilities, code quality issues, and test gaps.",
      {
        project_id: z.string().describe("The project UUID"),
        file_paths: z.array(z.string()).optional().describe("Specific files to analyze"),
        categories: z.array(z.string()).optional().describe("Analysis categories (e.g., 'security', 'quality', 'testing')"),
      },
      async ({ project_id, file_paths, categories }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ findings: Array<{ severity: string; category: string; file: string; line: number; message: string; recommendation: string }>; summary: { critical: number; high: number; medium: number; low: number } }>(
            `/api/v1/sast/analyze`,
            "POST",
            { project_id, file_paths, categories }
          );

          let output = `## SAST Analysis Results\n\n`;
          output += `**Summary:** ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium, ${result.summary.low} low\n\n`;
          (result.findings || []).slice(0, 20).forEach((f, i) => {
            const emoji = f.severity === "critical" ? "🔴" : f.severity === "high" ? "🟠" : f.severity === "medium" ? "🟡" : "🟢";
            output += `${i + 1}. ${emoji} **${f.category}** in \`${f.file}:${f.line}\`\n   ${f.message}\n   **Fix:** ${f.recommendation}\n\n`;
          });

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // Tool: argus_sast_scan_pr - Scan a pull request
    this.server.tool(
      "argus_sast_scan_pr",
      "Scan a pull request for security issues, test coverage gaps, and code quality problems.",
      {
        project_id: z.string().describe("The project UUID"),
        pr_number: z.number().describe("Pull request number"),
        repository: z.string().optional().describe("Repository name (owner/repo)"),
      },
      async ({ project_id, pr_number, repository }) => {
        try {
          await this.requireAuth();
          const result = await this.callBrainAPIWithAuth<{ findings: Array<{ severity: string; file: string; line: number; message: string }>; risk_level: string; tests_needed: string[] }>(
            `/api/v1/sast/scan-pr`,
            "POST",
            { project_id, pr_number, repository }
          );

          let output = `## PR Scan: #${pr_number}\n\n**Risk Level:** ${result.risk_level}\n\n`;
          if (result.findings?.length) {
            output += `### Findings (${result.findings.length})\n\n`;
            result.findings.forEach((f, i) => {
              output += `${i + 1}. **${f.severity}** \`${f.file}:${f.line}\` — ${f.message}\n`;
            });
          }
          if (result.tests_needed?.length) {
            output += `\n### Tests Needed\n`;
            result.tests_needed.forEach(t => { output += `- ${t}\n`; });
          }

          return { content: [{ type: "text" as const, text: output }] };
        } catch (error) { return this.handleError(error); }
      }
    );

    // =========================================================================
    // MCP RESOURCES - Contextual data for AI assistants
    // =========================================================================

    // Resource: argus://projects - List all projects
    this.server.resource(
      "projects",
      "argus://projects",
      { description: "List of all Skopaq projects with their configuration and quality status" },
      async () => {
        try {
          const accessToken = await this.getAccessToken();
          if (!accessToken) {
            return { contents: [{ uri: "argus://projects", text: "Authentication required. Run argus_auth first.", mimeType: "text/plain" }] };
          }
          const result = await this.callBrainAPIWithAuth<ProjectsResponse>(
            `/api/v1/projects`,
            "GET"
          );
          return {
            contents: [{
              uri: "argus://projects",
              text: JSON.stringify(result.projects || [], null, 2),
              mimeType: "application/json",
            }],
          };
        } catch (error) {
          return { contents: [{ uri: "argus://projects", text: `Error: ${error instanceof Error ? error.message : "Unknown"}`, mimeType: "text/plain" }] };
        }
      }
    );

    // Resource: argus://integrations - Connected integrations
    this.server.resource(
      "integrations",
      "argus://integrations",
      { description: "All connected integration platforms and their sync status" },
      async () => {
        try {
          const accessToken = await this.getAccessToken();
          if (!accessToken) {
            return { contents: [{ uri: "argus://integrations", text: "Authentication required.", mimeType: "text/plain" }] };
          }
          const result = await this.callBrainAPIWithAuth<{ integrations: unknown[] }>(
            `/api/v1/integrations`,
            "GET"
          );
          return {
            contents: [{
              uri: "argus://integrations",
              text: JSON.stringify(result.integrations || [], null, 2),
              mimeType: "application/json",
            }],
          };
        } catch (error) {
          return { contents: [{ uri: "argus://integrations", text: `Error: ${error instanceof Error ? error.message : "Unknown"}`, mimeType: "text/plain" }] };
        }
      }
    );

    // Resource: argus://schedules - Active schedules
    this.server.resource(
      "schedules",
      "argus://schedules",
      { description: "All active test schedules with cron configuration and run status" },
      async () => {
        try {
          const accessToken = await this.getAccessToken();
          if (!accessToken) {
            return { contents: [{ uri: "argus://schedules", text: "Authentication required.", mimeType: "text/plain" }] };
          }
          const result = await this.callBrainAPIWithAuth<{ schedules: unknown[] }>(
            `/api/v1/schedules`,
            "GET"
          );
          return {
            contents: [{
              uri: "argus://schedules",
              text: JSON.stringify(result.schedules || [], null, 2),
              mimeType: "application/json",
            }],
          };
        } catch (error) {
          return { contents: [{ uri: "argus://schedules", text: `Error: ${error instanceof Error ? error.message : "Unknown"}`, mimeType: "text/plain" }] };
        }
      }
    );

    // =========================================================================
    // MCP PROMPTS - Reusable prompt templates
    // =========================================================================

    // Prompt: test-plan - Generate a comprehensive test plan
    this.server.prompt(
      "test-plan",
      "Generate a comprehensive E2E test plan for a URL or project, covering critical user flows, edge cases, and priority testing areas.",
      {
        url: z.string().optional().describe("Application URL to generate test plan for"),
        project_id: z.string().optional().describe("Skopaq project UUID for context"),
        focus_areas: z.string().optional().describe("Comma-separated areas to focus on (e.g., 'auth, checkout, search')"),
      },
      async ({ url, project_id, focus_areas }) => {
        let context = "";
        if (project_id) {
          try {
            const stats = await this.callBrainAPIWithAuth<BrainQualityStatsResponse>(
              `/api/v1/quality/stats?project_id=${project_id}`,
              "GET"
            );
            context = `\n\nProject context: ${stats.stats.total_events} events tracked, ${stats.stats.coverage_rate}% coverage, ${stats.stats.total_generated_tests} tests generated.`;
          } catch { /* ignore if project context unavailable */ }
        }

        return {
          messages: [{
            role: "user" as const,
            content: {
              type: "text" as const,
              text: `Generate a comprehensive E2E test plan for ${url ? `the application at ${url}` : "the project"}.${context}${focus_areas ? `\n\nFocus areas: ${focus_areas}` : ""}\n\nPlease include:\n1. Critical user flows to test (prioritized)\n2. Edge cases and negative scenarios\n3. API integration tests needed\n4. Accessibility checks\n5. Performance considerations\n6. Mobile/responsive test scenarios\n7. Estimated effort and priority for each test`,
            },
          }],
        };
      }
    );

    // Prompt: failure-analysis - Analyze a test failure
    this.server.prompt(
      "failure-analysis",
      "Analyze a test failure with full context including error messages, screenshots, and recent code changes.",
      {
        error_message: z.string().describe("The error message from the failed test"),
        test_name: z.string().optional().describe("Name of the failed test"),
        project_id: z.string().optional().describe("Project UUID for additional context"),
        stack_trace: z.string().optional().describe("Full stack trace if available"),
      },
      async ({ error_message, test_name, project_id, stack_trace }) => {
        return {
          messages: [{
            role: "user" as const,
            content: {
              type: "text" as const,
              text: `Analyze this test failure and provide root cause analysis with actionable fixes.\n\n**Test:** ${test_name || "Unknown"}\n**Error:** ${error_message}${stack_trace ? `\n**Stack Trace:**\n\`\`\`\n${stack_trace}\n\`\`\`` : ""}${project_id ? `\n**Project:** ${project_id}` : ""}\n\nPlease provide:\n1. Most likely root cause\n2. Whether this is a test issue or application bug\n3. Specific fix recommendation (with code if possible)\n4. Similar patterns to watch for\n5. Whether self-healing could fix this automatically`,
            },
          }],
        };
      }
    );

    // Prompt: coverage-review - Review test coverage gaps
    this.server.prompt(
      "coverage-review",
      "Review test coverage gaps and suggest priority areas for new tests based on risk and usage data.",
      {
        project_id: z.string().describe("Project UUID to review"),
      },
      async ({ project_id }) => {
        let context = "";
        try {
          const [gaps, risks] = await Promise.all([
            this.callBrainAPIWithAuth<CoverageGapsResponse>(`/api/v1/quality/coverage-gaps?project_id=${project_id}`, "GET"),
            this.callBrainAPIWithAuth<BrainRiskScoresResponse>(`/api/v1/quality/risk-scores?project_id=${project_id}`, "GET"),
          ]);
          context = `\n\nCoverage gaps found: ${JSON.stringify(gaps.gaps?.slice(0, 5))}\nTop risks: ${JSON.stringify(risks.risk_scores?.slice(0, 5))}`;
        } catch { /* proceed without context */ }

        return {
          messages: [{
            role: "user" as const,
            content: {
              type: "text" as const,
              text: `Review the test coverage for project ${project_id} and provide recommendations.${context}\n\nPlease provide:\n1. Critical untested areas (highest risk first)\n2. Recommended test types for each gap (E2E, API, unit)\n3. Priority ranking with effort estimates\n4. Quick wins (high value, low effort tests)\n5. Integration points that need testing`,
            },
          }],
        };
      }
    );

    // Prompt: deployment-checklist - Pre-deployment testing checklist
    this.server.prompt(
      "deployment-checklist",
      "Generate a pre-deployment testing checklist tailored to the project's stack and recent changes.",
      {
        project_id: z.string().describe("Project UUID"),
        branch: z.string().optional().describe("Branch being deployed"),
        environment: z.string().optional().describe("Target environment (staging, production)"),
      },
      async ({ project_id, branch, environment }) => {
        return {
          messages: [{
            role: "user" as const,
            content: {
              type: "text" as const,
              text: `Generate a pre-deployment testing checklist for project ${project_id}${branch ? ` (branch: ${branch})` : ""}${environment ? ` targeting ${environment}` : ""}.\n\nPlease include:\n1. Smoke tests (critical path verification)\n2. Regression tests for recently changed areas\n3. Integration verification checklist\n4. Performance baseline checks\n5. Security scan checklist\n6. Accessibility verification\n7. Rollback criteria\n8. Post-deployment monitoring checklist`,
            },
          }],
        };
      }
    );
  }
}

// OAuth Durable Object for state management
export class MCPOAuth {
  state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/store") {
      const { key, value } = await request.json() as { key: string; value: unknown };
      await this.state.storage.put(key, value);
      return new Response("OK");
    }

    if (url.pathname === "/get") {
      const { key } = await request.json() as { key: string };
      const value = await this.state.storage.get(key);
      return Response.json({ value });
    }

    return new Response("Not found", { status: 404 });
  }
}

// Legacy class stub for migration (will be deleted in v6 migration)
export class SkopaqMcpAgent extends McpAgent<EnvWithKV> {
  server = new McpServer({
    name: "Legacy Skopaq MCP Agent",
    version: "0.0.0",
  });
  async init() {}
}

// Export the Skopaq MCP Agent with Sentry error tracking
export default Sentry.withSentry(
  (env: Env) => ({
    dsn: env.SENTRY_DSN,
    environment: "production",
    release: "argus-mcp-server@3.0.0",
    tracesSampleRate: 0.1,
  }),
  {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
      const url = new URL(request.url);

      // Handle the SSE endpoint for MCP (deprecated SSE protocol)
      if (url.pathname === "/sse" || url.pathname === "/sse/message") {
      return SkopaqMcpAgentSQLite.serveSSE("/sse").fetch(request, env, ctx);
    }

    // Handle the Streamable-HTTP endpoint for MCP (new protocol)
    if (url.pathname === "/mcp") {
      return SkopaqMcpAgentSQLite.serve("/mcp").fetch(request, env, ctx);
    }

    // Root endpoint - show info
    if (url.pathname === "/") {
      return Response.json({
        name: "Skopaq MCP Server",
        version: "3.0.0",
        description: "Model Context Protocol server for Skopaq E2E Testing Agent - Full IDE Integration with Next-Gen AI Testing Intelligence",
        endpoint: "/sse",
        tools: {
          authentication: [
            "argus_auth",
            "argus_auth_complete",
            "argus_auth_status",
            "argus_auth_logout",
          ],
          core: [
            "argus_health",
            "argus_discover",
            "argus_act",
            "argus_test",
            "argus_extract",
            "argus_agent",
            "argus_generate_test",
          ],
          quality_intelligence: [
            "argus_quality_score",
            "argus_quality_stats",
            "argus_risk_scores",
          ],
          production_events: [
            "argus_events",
            "argus_event_triage",
            "argus_test_from_event",
            "argus_batch_generate",
          ],
          test_management: [
            "argus_tests",
            "argus_test_review",
          ],
          self_healing: [
            "argus_healing_config",
            "argus_healing_patterns",
            "argus_healing_stats",
            "argus_healing_review",
          ],
          smart_insights: [
            "argus_what_to_test",
            "argus_coverage_gaps",
            "argus_dashboard",
            "argus_ask",
          ],
          projects: [
            "argus_projects",
          ],
          sync: [
            "argus_sync_push",
            "argus_sync_pull",
            "argus_sync_status",
            "argus_sync_resolve",
          ],
          export: [
            "argus_export",
            "argus_export_languages",
          ],
          recording: [
            "argus_recording_to_test",
            "argus_recording_snippet",
          ],
          collaboration: [
            "argus_presence",
            "argus_comments",
          ],
          discovery: [
            "argus_discovery_start",
            "argus_discovery_flows",
            "argus_discovery_generate",
            "argus_discovery_compare",
          ],
          time_travel: [
            "argus_time_travel_checkpoints",
            "argus_time_travel_history",
            "argus_time_travel_replay",
            "argus_time_travel_fork",
            "argus_time_travel_compare",
          ],
          cicd: [
            "argus_cicd_test_impact",
            "argus_cicd_deployment_risk",
            "argus_cicd_builds",
            "argus_cicd_pipelines",
          ],
          correlations: [
            "argus_correlations_timeline",
            "argus_correlations_root_cause",
            "argus_correlations_insights",
            "argus_correlations_query",
          ],
          api_testing: [
            "argus_api_discover",
            "argus_api_generate",
            "argus_api_run",
          ],
          scheduling: [
            "argus_schedule_create",
            "argus_schedule_list",
            "argus_schedule_run",
            "argus_schedule_history",
          ],
          visual_ai: [
            "argus_visual_capture",
            "argus_visual_compare",
            "argus_visual_baseline",
            "argus_visual_baselines",
            "argus_visual_analyze",
          ],
        },
        total_tools: 65,
        documentation: "https://github.com/raphaenterprises-ai/argus-e2e-testing-agent",
      });
    }

    // Screenshot serving endpoint (authenticated via signed token)
    // URL format: /screenshot/{key}?t={expiry.signature}
    // Single parameter to avoid & truncation in markdown/terminals
    if (url.pathname.startsWith("/screenshot/")) {
      const key = decodeURIComponent(url.pathname.slice("/screenshot/".length));
      // Support both new format (?t=) and legacy format (?token=&exp=)
      const newToken = url.searchParams.get("t");
      const legacyToken = url.searchParams.get("token");
      const legacyExp = url.searchParams.get("exp");

      let validation: { valid: boolean; expiry?: number; error?: string };

      if (newToken) {
        // New single-parameter format: ?t=expiry.signature
        validation = await validateScreenshotToken(newToken, key, env);
      } else if (legacyToken && legacyExp) {
        // Legacy format: ?token=signature&exp=expiry
        const expiry = parseInt(legacyExp, 10);
        if (isNaN(expiry) || Date.now() > expiry) {
          validation = { valid: false, error: "Token expired" };
        } else {
          // Reconstruct and validate legacy token
          const expectedToken = `${expiry}.${legacyToken}`;
          validation = await validateScreenshotToken(expectedToken, key, env);
        }
      } else {
        return new Response("Missing token parameter. Use ?t=token", { status: 401 });
      }

      if (!validation.valid) {
        const status = validation.error === "Token expired" ? 403 : 401;
        return new Response(validation.error || "Invalid token", { status });
      }

      // Fetch from R2
      try {
        const object = await env.SCREENSHOTS.get(key);
        if (!object) {
          return new Response("Screenshot not found", { status: 404 });
        }

        const data = await object.arrayBuffer();
        return new Response(data, {
          headers: {
            "Content-Type": "image/png",
            "Cache-Control": "private, max-age=3600",
            "X-Screenshot-Key": key,
          },
        });
      } catch (error) {
        console.error("[Screenshot] Fetch error:", error);
        return new Response("Failed to fetch screenshot", { status: 500 });
      }
    }

    return new Response("Not found", { status: 404 });
    },
  } as ExportedHandler<Env>
);

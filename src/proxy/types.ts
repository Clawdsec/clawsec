/**
 * Proxy Server Type Definitions
 * Types for the standalone HTTP proxy server
 */

import type { ClawsecConfig } from '../config/schema.js';
import type { AnalysisResult, Detection } from '../engine/types.js';

/**
 * Configuration for the proxy server
 */
export interface ProxyConfig {
  /** Port to listen on */
  port: number;
  /** Host to bind to (default: '127.0.0.1') */
  host?: string;
  /** Clawsec configuration for analysis */
  clawsecConfig: ClawsecConfig;
}

/**
 * Request body for the /analyze endpoint
 */
export interface ProxyRequest {
  /** Name of the tool being called */
  toolName: string;
  /** Input parameters to the tool */
  toolInput: Record<string, unknown>;
  /** Optional session identifier */
  sessionId?: string;
  /** Optional user identifier */
  userId?: string;
}

/**
 * Response from the /analyze endpoint
 */
export interface ProxyResponse {
  /** Whether the request is allowed */
  allowed: boolean;
  /** Human-readable message explaining the decision */
  message?: string;
  /** Information about pending approval (if action is 'confirm') */
  pendingApproval?: {
    /** Unique identifier for the approval */
    id: string;
    /** Timeout in seconds before the approval expires */
    timeout: number;
  };
  /** Filtered/sanitized input (if any modifications were made) */
  filteredInput?: Record<string, unknown>;
  /** Analysis result details */
  analysis?: {
    /** Recommended action */
    action: AnalysisResult['action'];
    /** List of detections */
    detections: Detection[];
    /** Whether result was cached */
    cached: boolean;
    /** Analysis duration in milliseconds */
    durationMs?: number;
  };
}

/**
 * Response from /approve/:id and /deny/:id endpoints
 */
export interface ApprovalActionResponse {
  /** Whether the operation succeeded */
  success: boolean;
  /** Human-readable message */
  message: string;
}

/**
 * Response from /status endpoint
 */
export interface StatusResponse {
  /** Whether the server is active and accepting requests */
  active: boolean;
  /** Configuration summary */
  config: {
    /** Configured port */
    port: number;
    /** Configured host */
    host: string;
    /** Whether global detection is enabled */
    enabled: boolean;
  };
  /** Number of pending approvals */
  pendingApprovals: number;
}

/**
 * Response from /health endpoint
 */
export interface HealthResponse {
  /** Health status */
  status: 'ok';
}

/**
 * Error response for API errors
 */
export interface ErrorResponse {
  /** Error flag */
  error: true;
  /** Error message */
  message: string;
  /** HTTP status code */
  statusCode: number;
}

/**
 * Proxy server interface
 */
export interface ProxyServer {
  /** Start the server */
  start(): Promise<void>;
  /** Stop the server */
  stop(): Promise<void>;
  /** Get the actual port the server is listening on */
  getPort(): number;
}

/**
 * HTTP request handler function
 */
export type RequestHandler = (
  req: ProxyHttpRequest,
  res: ProxyHttpResponse
) => Promise<void> | void;

/**
 * Simplified HTTP request interface
 */
export interface ProxyHttpRequest {
  method: string;
  url: string;
  body?: unknown;
}

/**
 * Simplified HTTP response interface
 */
export interface ProxyHttpResponse {
  statusCode: number;
  json(data: unknown): void;
  end(): void;
}

/**
 * Standalone Proxy Server Module
 * HTTP proxy server for tool call analysis without OpenClaw integration
 */

// Types
export type {
  ProxyConfig,
  ProxyRequest,
  ProxyResponse,
  ApprovalActionResponse,
  StatusResponse,
  HealthResponse,
  ErrorResponse,
  ProxyServer,
  RequestHandler,
  ProxyHttpRequest,
  ProxyHttpResponse,
} from './types.js';

// Middleware
export {
  toToolCallContext,
  toProxyResponse,
  AnalysisMiddleware,
  ValidationError,
  createAnalysisMiddleware,
} from './middleware.js';

// Server
export {
  HttpProxyServer,
  createProxyServer,
} from './server.js';

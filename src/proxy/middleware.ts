/**
 * Proxy Middleware
 * Request processing middleware that bridges HTTP requests to the detection engine
 */

import type { ToolCallContext, AnalysisResult, Analyzer } from '../engine/types.js';
import type {
  ApprovalStore,
  PendingApprovalInput,
} from '../approval/types.js';
import type {
  ProxyRequest,
  ProxyResponse,
  ApprovalActionResponse,
  StatusResponse,
  HealthResponse,
  ProxyConfig,
} from './types.js';

/** Default approval timeout in seconds */
const DEFAULT_APPROVAL_TIMEOUT_SECONDS = 300;

/**
 * Generate a unique approval ID
 */
function generateApprovalId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).slice(2, 10);
  return `approval-${timestamp}-${random}`;
}

/**
 * Convert ProxyRequest to ToolCallContext for analysis
 */
export function toToolCallContext(request: ProxyRequest): ToolCallContext {
  const context: ToolCallContext = {
    toolName: request.toolName,
    toolInput: request.toolInput,
  };

  // Extract URL from common tool input patterns
  if (typeof request.toolInput.url === 'string') {
    context.url = request.toolInput.url;
  }

  return context;
}

/**
 * Convert AnalysisResult to ProxyResponse
 */
export function toProxyResponse(
  result: AnalysisResult,
  pendingApprovalId?: string,
  approvalTimeoutSeconds?: number
): ProxyResponse {
  const response: ProxyResponse = {
    allowed: result.action === 'allow' || result.action === 'log',
    analysis: {
      action: result.action,
      detections: result.detections,
      cached: result.cached,
      durationMs: result.durationMs,
    },
  };

  // Add message based on action
  switch (result.action) {
    case 'allow':
      response.message = 'Request allowed';
      break;
    case 'block':
      response.message = result.primaryDetection
        ? `Request blocked: ${result.primaryDetection.reason}`
        : 'Request blocked';
      break;
    case 'confirm':
      response.message = result.primaryDetection
        ? `Approval required: ${result.primaryDetection.reason}`
        : 'Approval required';
      if (pendingApprovalId) {
        response.pendingApproval = {
          id: pendingApprovalId,
          timeout: approvalTimeoutSeconds ?? DEFAULT_APPROVAL_TIMEOUT_SECONDS,
        };
      }
      break;
    case 'warn':
      response.message = result.primaryDetection
        ? `Warning: ${result.primaryDetection.reason}`
        : 'Warning';
      response.allowed = true;
      break;
    case 'log':
      response.message = 'Request logged and allowed';
      break;
  }

  return response;
}

/**
 * Middleware for processing analysis requests
 */
export class AnalysisMiddleware {
  private readonly analyzer: Analyzer;
  private readonly approvalStore: ApprovalStore;
  private readonly approvalTimeoutSeconds: number;

  constructor(
    analyzer: Analyzer,
    approvalStore: ApprovalStore,
    approvalTimeoutSeconds: number = DEFAULT_APPROVAL_TIMEOUT_SECONDS
  ) {
    this.analyzer = analyzer;
    this.approvalStore = approvalStore;
    this.approvalTimeoutSeconds = approvalTimeoutSeconds;
  }

  /**
   * Process an analysis request
   */
  async analyze(request: Record<string, unknown>): Promise<ProxyResponse> {
    // Validate and cast request
    const toolName = request.toolName;
    if (!toolName || typeof toolName !== 'string') {
      throw new ValidationError('toolName is required and must be a string');
    }
    const toolInput = request.toolInput;
    if (!toolInput || typeof toolInput !== 'object' || toolInput === null) {
      throw new ValidationError('toolInput is required and must be an object');
    }
    
    // Build typed request
    const typedRequest: ProxyRequest = {
      toolName,
      toolInput: toolInput as Record<string, unknown>,
      sessionId: typeof request.sessionId === 'string' ? request.sessionId : undefined,
      userId: typeof request.userId === 'string' ? request.userId : undefined,
    };

    // Convert to ToolCallContext
    const context = toToolCallContext(typedRequest);

    // Run analysis
    const result = await this.analyzer.analyze(context);

    // If action is 'confirm', create a pending approval
    let pendingApprovalId: string | undefined;
    if (result.action === 'confirm' && result.primaryDetection) {
      pendingApprovalId = generateApprovalId();
      const now = Date.now();
      const expiresAt = now + this.approvalTimeoutSeconds * 1000;

      const approvalInput: PendingApprovalInput = {
        id: pendingApprovalId,
        createdAt: now,
        expiresAt,
        detection: result.primaryDetection,
        toolCall: context,
      };

      this.approvalStore.add(approvalInput);
    }

    return toProxyResponse(result, pendingApprovalId, this.approvalTimeoutSeconds);
  }

  /**
   * Approve a pending request
   */
  approve(id: string, approvedBy?: string): ApprovalActionResponse {
    const record = this.approvalStore.get(id);

    if (!record) {
      return {
        success: false,
        message: `Approval not found: ${id}`,
      };
    }

    if (record.status !== 'pending') {
      return {
        success: false,
        message: `Approval already ${record.status}: ${id}`,
      };
    }

    const success = this.approvalStore.approve(id, approvedBy);
    return {
      success,
      message: success
        ? `Approved: ${id}`
        : `Failed to approve: ${id}`,
    };
  }

  /**
   * Deny a pending request
   */
  deny(id: string): ApprovalActionResponse {
    const record = this.approvalStore.get(id);

    if (!record) {
      return {
        success: false,
        message: `Approval not found: ${id}`,
      };
    }

    if (record.status !== 'pending') {
      return {
        success: false,
        message: `Approval already ${record.status}: ${id}`,
      };
    }

    const success = this.approvalStore.deny(id);
    return {
      success,
      message: success
        ? `Denied: ${id}`
        : `Failed to deny: ${id}`,
    };
  }

  /**
   * Get server status
   */
  getStatus(config: ProxyConfig, actualPort?: number): StatusResponse {
    const pendingApprovals = this.approvalStore.getPending();
    return {
      active: true,
      config: {
        port: actualPort ?? config.port,
        host: config.host ?? '127.0.0.1',
        enabled: config.clawsecConfig.global?.enabled ?? true,
      },
      pendingApprovals: pendingApprovals.length,
    };
  }

  /**
   * Get health status
   */
  getHealth(): HealthResponse {
    return { status: 'ok' };
  }
}

/**
 * Custom error for validation failures
 */
export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

/**
 * Create an analysis middleware instance
 */
export function createAnalysisMiddleware(
  analyzer: Analyzer,
  approvalStore: ApprovalStore,
  approvalTimeoutSeconds?: number
): AnalysisMiddleware {
  return new AnalysisMiddleware(analyzer, approvalStore, approvalTimeoutSeconds);
}

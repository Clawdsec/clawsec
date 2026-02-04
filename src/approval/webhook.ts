/**
 * Webhook Approval Client
 * Handles approval requests via external webhooks (Slack, Discord, custom APIs, etc.)
 */

import type { Detection, ToolCallContext } from '../engine/types.js';
import type { ApprovalResult, ApprovalStore, PendingApprovalRecord } from './types.js';
import type { WebhookApproval } from '../config/schema.js';
import { getDefaultApprovalStore } from './store.js';

/**
 * Request sent to the webhook endpoint
 */
export interface WebhookApprovalRequest {
  /** Unique identifier for this approval request */
  id: string;
  /** The detection that triggered this approval request */
  detection: Detection;
  /** Information about the tool call */
  toolCall: {
    name: string;
    input: Record<string, unknown>;
  };
  /** Timestamp when the request was created (ms since epoch) */
  timestamp: number;
  /** Timestamp when the approval expires (ms since epoch) */
  expiresAt: number;
  /** Optional callback URL for async approval */
  callbackUrl?: string;
}

/**
 * Response from the webhook endpoint
 */
export interface WebhookApprovalResponse {
  /** Whether the action was approved */
  approved: boolean;
  /** Who approved/denied the action */
  approvedBy?: string;
  /** Reason for the decision */
  reason?: string;
}

/**
 * Result of a webhook approval request
 */
export interface WebhookApprovalResult {
  /** Whether the webhook request was successful */
  success: boolean;
  /** Response from the webhook (if successful) */
  response?: WebhookApprovalResponse;
  /** Error message (if unsuccessful) */
  error?: string;
  /** True if waiting for async callback (202 response) */
  waitingForCallback: boolean;
}

/**
 * Interface for the webhook approval client
 */
export interface WebhookApprovalClient {
  /** Send approval request to external system */
  requestApproval(request: WebhookApprovalRequest): Promise<WebhookApprovalResult>;
  /** Handle callback from external system */
  handleCallback(id: string, response: WebhookApprovalResponse): ApprovalResult;
  /** Check if webhook approval is enabled */
  isEnabled(): boolean;
}

/**
 * HTTP client interface for making requests (allows mocking in tests)
 */
export interface HttpClient {
  /** Make a POST request */
  post(
    url: string,
    body: unknown,
    options: { headers?: Record<string, string>; timeoutMs?: number }
  ): Promise<HttpResponse>;
}

/**
 * HTTP response interface
 */
export interface HttpResponse {
  /** HTTP status code */
  status: number;
  /** Response body (parsed JSON) */
  body: unknown;
}

/**
 * Configuration for the webhook approval client
 */
export interface WebhookApprovalClientConfig {
  /** Webhook configuration from clawsec config */
  webhookConfig: WebhookApproval;
  /** Optional custom HTTP client (for testing) */
  httpClient?: HttpClient;
  /** Approval store to use */
  store?: ApprovalStore;
  /** Optional callback URL template (use {id} as placeholder) */
  callbackUrlTemplate?: string;
}

/**
 * Default HTTP client implementation using fetch
 */
export class FetchHttpClient implements HttpClient {
  async post(
    url: string,
    body: unknown,
    options: { headers?: Record<string, string>; timeoutMs?: number }
  ): Promise<HttpResponse> {
    const controller = new AbortController();
    const timeoutId = options.timeoutMs
      ? setTimeout(() => controller.abort(), options.timeoutMs)
      : undefined;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      let responseBody: unknown;
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        responseBody = await response.json();
      } else {
        responseBody = await response.text();
      }

      return {
        status: response.status,
        body: responseBody,
      };
    } finally {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    }
  }
}

/**
 * Default webhook approval client implementation
 */
export class DefaultWebhookApprovalClient implements WebhookApprovalClient {
  private config: WebhookApproval;
  private httpClient: HttpClient;
  private store: ApprovalStore;
  private callbackUrlTemplate?: string;

  constructor(config: WebhookApprovalClientConfig) {
    this.config = config.webhookConfig;
    this.httpClient = config.httpClient ?? new FetchHttpClient();
    this.store = config.store ?? getDefaultApprovalStore();
    this.callbackUrlTemplate = config.callbackUrlTemplate;
  }

  /**
   * Check if webhook approval is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled && !!this.config.url;
  }

  /**
   * Send approval request to external system
   */
  async requestApproval(request: WebhookApprovalRequest): Promise<WebhookApprovalResult> {
    // Check if enabled
    if (!this.isEnabled()) {
      return {
        success: false,
        error: 'Webhook approval is not enabled or URL is not configured',
        waitingForCallback: false,
      };
    }

    // Build callback URL if template is provided
    const callbackUrl = this.callbackUrlTemplate
      ? this.callbackUrlTemplate.replace('{id}', request.id)
      : request.callbackUrl;

    // Build the request payload
    const payload: WebhookApprovalRequest = {
      ...request,
      callbackUrl,
    };

    try {
      const response = await this.httpClient.post(
        this.config.url!,
        payload,
        {
          headers: this.config.headers ?? {},
          timeoutMs: this.config.timeout * 1000,
        }
      );

      return this.handleResponse(response);
    } catch (error) {
      return this.handleError(error);
    }
  }

  /**
   * Handle callback from external system
   */
  handleCallback(id: string, response: WebhookApprovalResponse): ApprovalResult {
    // Validate ID
    if (!id || typeof id !== 'string' || id.trim() === '') {
      return {
        success: false,
        message: 'Invalid approval ID: ID cannot be empty',
      };
    }

    const trimmedId = id.trim();

    // Get the record
    const record = this.store.get(trimmedId);

    if (!record) {
      return {
        success: false,
        message: `Approval not found: No pending approval with ID "${trimmedId}"`,
      };
    }

    // Check if expired
    if (record.status === 'expired') {
      return {
        success: false,
        message: `Approval expired: The approval "${trimmedId}" has expired`,
        record,
      };
    }

    // Check if already processed
    if (record.status !== 'pending') {
      return {
        success: false,
        message: `Approval already ${record.status}: The approval "${trimmedId}" was already ${record.status}`,
        record,
      };
    }

    // Process the response
    if (response.approved) {
      const success = this.store.approve(trimmedId, response.approvedBy ?? 'webhook');
      if (!success) {
        return {
          success: false,
          message: `Failed to approve: Unable to approve "${trimmedId}"`,
          record: this.store.get(trimmedId),
        };
      }

      const approvedRecord = this.store.get(trimmedId);
      return {
        success: true,
        message: this.formatApprovalMessage(approvedRecord!, response),
        record: approvedRecord,
      };
    } else {
      const success = this.store.deny(trimmedId);
      if (!success) {
        return {
          success: false,
          message: `Failed to deny: Unable to deny "${trimmedId}"`,
          record: this.store.get(trimmedId),
        };
      }

      const deniedRecord = this.store.get(trimmedId);
      return {
        success: true,
        message: this.formatDenialMessage(deniedRecord!, response),
        record: deniedRecord,
      };
    }
  }

  /**
   * Handle HTTP response
   */
  private handleResponse(response: HttpResponse): WebhookApprovalResult {
    // Handle 202 Accepted (async approval)
    if (response.status === 202) {
      return {
        success: true,
        waitingForCallback: true,
      };
    }

    // Handle success (200)
    if (response.status === 200) {
      const body = response.body;

      // Validate response format
      if (!this.isValidApprovalResponse(body)) {
        return {
          success: false,
          error: 'Invalid response format: expected { approved: boolean }',
          waitingForCallback: false,
        };
      }

      return {
        success: true,
        response: body as WebhookApprovalResponse,
        waitingForCallback: false,
      };
    }

    // Handle client errors (4xx)
    if (response.status >= 400 && response.status < 500) {
      const errorMessage = this.extractErrorMessage(response.body);
      return {
        success: false,
        error: `Client error (${response.status}): ${errorMessage}`,
        waitingForCallback: false,
      };
    }

    // Handle server errors (5xx)
    if (response.status >= 500) {
      const errorMessage = this.extractErrorMessage(response.body);
      return {
        success: false,
        error: `Server error (${response.status}): ${errorMessage}`,
        waitingForCallback: false,
      };
    }

    // Handle other status codes
    return {
      success: false,
      error: `Unexpected status code: ${response.status}`,
      waitingForCallback: false,
    };
  }

  /**
   * Handle HTTP errors
   */
  private handleError(error: unknown): WebhookApprovalResult {
    // Handle timeout (AbortError)
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        return {
          success: false,
          error: `Request timeout: Webhook did not respond within ${this.config.timeout} seconds`,
          waitingForCallback: false,
        };
      }

      // Handle network errors
      if (error.message.includes('fetch') || error.message.includes('network')) {
        return {
          success: false,
          error: `Network error: ${error.message}`,
          waitingForCallback: false,
        };
      }

      return {
        success: false,
        error: `Request failed: ${error.message}`,
        waitingForCallback: false,
      };
    }

    return {
      success: false,
      error: 'Unknown error occurred while making webhook request',
      waitingForCallback: false,
    };
  }

  /**
   * Validate that the response is a valid approval response
   */
  private isValidApprovalResponse(body: unknown): body is WebhookApprovalResponse {
    if (!body || typeof body !== 'object') {
      return false;
    }

    const response = body as Record<string, unknown>;
    return typeof response.approved === 'boolean';
  }

  /**
   * Extract error message from response body
   */
  private extractErrorMessage(body: unknown): string {
    if (!body) {
      return 'No error details provided';
    }

    if (typeof body === 'string') {
      return body;
    }

    if (typeof body === 'object') {
      const obj = body as Record<string, unknown>;
      if (typeof obj.error === 'string') {
        return obj.error;
      }
      if (typeof obj.message === 'string') {
        return obj.message;
      }
    }

    return 'Unknown error';
  }

  /**
   * Format approval message
   */
  private formatApprovalMessage(record: PendingApprovalRecord, response: WebhookApprovalResponse): string {
    const toolName = record.toolCall.toolName;
    const approver = response.approvedBy ? ` by ${response.approvedBy}` : ' via webhook';
    const reason = response.reason ? ` (${response.reason})` : '';

    return `Approved${approver}: The action using tool "${toolName}" has been approved${reason}`;
  }

  /**
   * Format denial message
   */
  private formatDenialMessage(record: PendingApprovalRecord, response: WebhookApprovalResponse): string {
    const toolName = record.toolCall.toolName;
    const denier = response.approvedBy ? ` by ${response.approvedBy}` : ' via webhook';
    const reason = response.reason ? ` (${response.reason})` : '';

    return `Denied${denier}: The action using tool "${toolName}" has been denied${reason}`;
  }
}

/**
 * Create a webhook approval client with the given configuration
 */
export function createWebhookApprovalClient(
  config: WebhookApprovalClientConfig
): DefaultWebhookApprovalClient {
  return new DefaultWebhookApprovalClient(config);
}

/**
 * Default webhook config (disabled)
 */
const DEFAULT_WEBHOOK_CONFIG: WebhookApproval = {
  enabled: false,
  url: undefined,
  timeout: 30,
  headers: {},
};

/**
 * Default singleton client instance
 */
let defaultClient: DefaultWebhookApprovalClient | null = null;

/**
 * Get the default webhook approval client singleton
 */
export function getDefaultWebhookApprovalClient(): DefaultWebhookApprovalClient {
  if (!defaultClient) {
    defaultClient = createWebhookApprovalClient({
      webhookConfig: DEFAULT_WEBHOOK_CONFIG,
    });
  }
  return defaultClient;
}

/**
 * Set the default webhook approval client configuration
 */
export function configureDefaultWebhookApprovalClient(
  config: WebhookApprovalClientConfig
): DefaultWebhookApprovalClient {
  defaultClient = createWebhookApprovalClient(config);
  return defaultClient;
}

/**
 * Reset the default client (mainly for testing)
 */
export function resetDefaultWebhookApprovalClient(): void {
  defaultClient = null;
}

/**
 * Create a webhook approval request from a pending approval record
 */
export function createWebhookRequest(
  record: PendingApprovalRecord,
  callbackUrl?: string
): WebhookApprovalRequest {
  return {
    id: record.id,
    detection: record.detection,
    toolCall: {
      name: record.toolCall.toolName,
      input: record.toolCall.toolInput,
    },
    timestamp: record.createdAt,
    expiresAt: record.expiresAt,
    callbackUrl,
  };
}

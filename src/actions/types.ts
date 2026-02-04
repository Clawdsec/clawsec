/**
 * Action Executor Types
 * Type definitions for the action execution system
 */

import type { ClawsecConfig } from '../config/index.js';
import type { AnalysisResult, ToolCallContext } from '../engine/types.js';

/**
 * Approval methods available for confirmation flow
 */
export type ApprovalMethod = 'native' | 'agent-confirm' | 'webhook';

/**
 * Context provided to action handlers
 */
export interface ActionContext {
  /** Result from the hybrid analyzer */
  analysis: AnalysisResult;
  /** Original tool call context */
  toolCall: ToolCallContext;
  /** Plugin configuration */
  config: ClawsecConfig;
}

/**
 * Pending approval details returned when action requires confirmation
 */
export interface PendingApproval {
  /** Unique identifier for this approval request */
  id: string;
  /** Timeout in seconds for the approval */
  timeout: number;
  /** Approval methods available for this request */
  methods: ApprovalMethod[];
}

/**
 * Result of executing an action
 */
export interface ActionResult {
  /** Whether the tool call is allowed to proceed */
  allowed: boolean;
  /** Human-readable message about the action taken */
  message?: string;
  /** Pending approval details (only for confirm action) */
  pendingApproval?: PendingApproval;
  /** Whether the action was logged for audit */
  logged: boolean;
}

/**
 * Interface for individual action handlers
 */
export interface ActionHandler {
  /** Execute the action and return the result */
  execute(context: ActionContext): Promise<ActionResult>;
}

/**
 * Main executor interface
 */
export interface ActionExecutor {
  /** Execute the appropriate action based on analysis result */
  execute(context: ActionContext): Promise<ActionResult>;
}

/**
 * Logger interface for action logging
 */
export interface ActionLogger {
  /** Log a debug message */
  debug(message: string, data?: Record<string, unknown>): void;
  /** Log an info message */
  info(message: string, data?: Record<string, unknown>): void;
  /** Log a warning message */
  warn(message: string, data?: Record<string, unknown>): void;
  /** Log an error message */
  error(message: string, data?: Record<string, unknown>): void;
}

/**
 * Default console logger implementation
 */
/* eslint-disable no-console */
export const consoleLogger: ActionLogger = {
  debug: (message, data) => {
    if (data) {
      console.debug(`[clawsec] ${message}`, data);
    } else {
      console.debug(`[clawsec] ${message}`);
    }
  },
  info: (message, data) => {
    if (data) {
      console.info(`[clawsec] ${message}`, data);
    } else {
      console.info(`[clawsec] ${message}`);
    }
  },
  warn: (message, data) => {
    if (data) {
      console.warn(`[clawsec] ${message}`, data);
    } else {
      console.warn(`[clawsec] ${message}`);
    }
  },
  error: (message, data) => {
    if (data) {
      console.error(`[clawsec] ${message}`, data);
    } else {
      console.error(`[clawsec] ${message}`);
    }
  },
};
/* eslint-enable no-console */

/**
 * No-op logger for testing or silent mode
 */
export const noOpLogger: ActionLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

/**
 * Create a logger based on log level
 */
export function createLogger(logLevel: 'debug' | 'info' | 'warn' | 'error'): ActionLogger {
  const levels = ['debug', 'info', 'warn', 'error'];
  const minLevel = levels.indexOf(logLevel);

  return {
    debug: (message: string, data?: Record<string, unknown>): void => {
      if (minLevel <= 0) consoleLogger.debug(message, data);
    },
    info: (message: string, data?: Record<string, unknown>): void => {
      if (minLevel <= 1) consoleLogger.info(message, data);
    },
    warn: (message: string, data?: Record<string, unknown>): void => {
      if (minLevel <= 2) consoleLogger.warn(message, data);
    },
    error: (message: string, data?: Record<string, unknown>): void => {
      if (minLevel <= 3) consoleLogger.error(message, data);
    },
  };
}

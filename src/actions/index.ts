/**
 * Action Executor Module
 * Re-exports for the action execution system
 */

// Types
export type {
  ActionContext,
  ActionResult,
  ActionHandler,
  ActionExecutor,
  ActionLogger,
  ApprovalMethod,
  PendingApproval,
} from './types.js';

export {
  consoleLogger,
  noOpLogger,
  createLogger,
} from './types.js';

// Block handler
export {
  BlockHandler,
  createBlockHandler,
  generateBlockMessage,
} from './block.js';

// Confirm handler
export {
  ConfirmHandler,
  createConfirmHandler,
  generateConfirmMessage,
  generateApprovalId,
  getEnabledApprovalMethods,
  getApprovalTimeout,
} from './confirm.js';

// Warn handler
export {
  WarnHandler,
  createWarnHandler,
  generateWarnMessage,
} from './warn.js';

// Log handler
export {
  LogHandler,
  createLogHandler,
} from './log.js';

// Main executor
export type { ExecutorConfig } from './executor.js';
export {
  DefaultActionExecutor,
  createActionExecutor,
  createDefaultActionExecutor,
} from './executor.js';

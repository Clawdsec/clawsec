/**
 * Before Tool Call Hook
 * Re-exports for the before-tool-call hook
 */

export type { BeforeToolCallHandlerOptions } from './handler.js';

export {
  createBeforeToolCallHandler,
  createDefaultBeforeToolCallHandler,
} from './handler.js';

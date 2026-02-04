/**
 * CLI Commands
 * Re-exports for all CLI commands
 */

// Types
export type {
  CLIOptions,
  StatusResult,
  TestResult,
  AuditEntry,
  AuditOptions,
  AuditResult,
} from './types.js';

// Status command
export {
  statusCommand,
  formatStatusResult,
} from './status.js';

// Test command
export {
  testCommand,
  formatTestResult,
} from './test.js';

// Audit command
export {
  auditCommand,
  formatAuditResult,
  addAuditEntry,
  clearAuditLog,
  getAuditLog,
  createAuditEntry,
} from './audit.js';

/**
 * CLI Command Types
 * Type definitions for CLI commands and results
 */

import type { ThreatCategory } from '../../engine/index.js';
import type { Severity } from '../../config/index.js';

/**
 * CLI options for all commands
 */
export interface CLIOptions {
  /** Path to clawsec.yaml config file */
  config?: string;
}

/**
 * Result of the status command
 */
export interface StatusResult {
  /** Path to the config file */
  configPath: string;
  /** Whether the config is valid */
  configValid: boolean;
  /** List of enabled rule names */
  enabledRules: string[];
  /** List of disabled rule names */
  disabledRules: string[];
  /** Any issues found with the configuration */
  issues: string[];
}

/**
 * Result of the test command
 */
export interface TestResult {
  /** Whether a threat was detected */
  detected: boolean;
  /** Category of threat detected (if any) */
  category?: ThreatCategory;
  /** Severity level */
  severity?: Severity;
  /** Confidence score 0-1 */
  confidence?: number;
  /** Reason for detection */
  reason?: string;
}

/**
 * Audit log entry for tracking detections
 */
export interface AuditEntry {
  /** Timestamp of the detection */
  timestamp: Date;
  /** Tool that was called */
  toolName: string;
  /** Category of threat detected */
  category: ThreatCategory;
  /** Severity level */
  severity: Severity;
  /** Action taken (block, warn, etc.) */
  action: string;
  /** Reason for the detection */
  reason: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Options for the audit command
 */
export interface AuditOptions {
  /** Maximum number of entries to show */
  limit?: number;
  /** Filter by category */
  category?: ThreatCategory;
}

/**
 * Result of the audit command
 */
export interface AuditResult {
  /** Audit entries matching the query */
  entries: AuditEntry[];
  /** Total entries in the log */
  totalEntries: number;
}

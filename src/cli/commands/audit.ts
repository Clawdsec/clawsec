/**
 * Audit Command
 * View and manage the audit log of detections
 */

import type { ThreatCategory } from '../../engine/index.js';
import type { Severity } from '../../config/index.js';
import type { AuditEntry, AuditOptions, AuditResult } from './types.js';

/**
 * In-memory audit log storage
 * In a production system, this would be persisted to disk or a database
 */
const auditLog: AuditEntry[] = [];

/**
 * Add an entry to the audit log
 * 
 * @param entry - The audit entry to add
 */
export function addAuditEntry(entry: Omit<AuditEntry, 'timestamp'>): void {
  auditLog.push({
    ...entry,
    timestamp: new Date(),
  });
}

/**
 * Clear all audit log entries
 * Primarily used for testing
 */
export function clearAuditLog(): void {
  auditLog.length = 0;
}

/**
 * Get the raw audit log (for testing)
 */
export function getAuditLog(): ReadonlyArray<AuditEntry> {
  return auditLog;
}

/**
 * Execute the audit command
 * 
 * @param options - Audit options for filtering and limiting results
 * @returns Audit result with filtered entries
 */
export async function auditCommand(options: AuditOptions = {}): Promise<AuditResult> {
  let entries = [...auditLog];

  // Filter by category if specified
  if (options.category) {
    entries = entries.filter(entry => entry.category === options.category);
  }

  // Sort by timestamp (newest first)
  entries.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

  // Apply limit if specified
  const limit = options.limit ?? 10;
  const limitedEntries = entries.slice(0, limit);

  return {
    entries: limitedEntries,
    totalEntries: auditLog.length,
  };
}

/**
 * Format a single audit entry for display
 */
function formatEntry(entry: AuditEntry, index: number): string {
  const timestamp = entry.timestamp.toISOString().replace('T', ' ').substring(0, 19);
  const severityColors: Record<Severity, string> = {
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'MEDIUM',
    low: 'LOW',
  };

  const lines: string[] = [];
  lines.push(`[${index + 1}] ${timestamp}`);
  lines.push(`    Tool: ${entry.toolName}`);
  lines.push(`    Category: ${entry.category} | Severity: ${severityColors[entry.severity]} | Action: ${entry.action}`);
  lines.push(`    Reason: ${entry.reason}`);

  return lines.join('\n');
}

/**
 * Format audit result for console output
 * 
 * @param result - Audit result to format
 * @param options - The options used for the query
 * @returns Formatted string for display
 */
export function formatAuditResult(result: AuditResult, options: AuditOptions = {}): string {
  const lines: string[] = [];

  lines.push('=== Audit Log ===');
  lines.push('');

  if (options.category) {
    lines.push(`Filter: category=${options.category}`);
  }
  
  lines.push(`Showing ${result.entries.length} of ${result.totalEntries} entries`);
  lines.push('');

  if (result.entries.length === 0) {
    lines.push('No audit entries found.');
  } else {
    for (let i = 0; i < result.entries.length; i++) {
      lines.push(formatEntry(result.entries[i], i));
      lines.push('');
    }
  }

  return lines.join('\n');
}

/**
 * Helper function to create an audit entry from detection data
 * This is used by the action handlers to log detections
 */
export function createAuditEntry(
  toolName: string,
  category: ThreatCategory,
  severity: Severity,
  action: string,
  reason: string,
  metadata?: Record<string, unknown>
): void {
  addAuditEntry({
    toolName,
    category,
    severity,
    action,
    reason,
    metadata,
  });
}

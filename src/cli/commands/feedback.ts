/**
 * Feedback Command
 * CLI command for submitting and viewing user feedback on detection accuracy
 */

import type { ThreatCategory } from '../../engine/index.js';
import type {
  FeedbackEntry,
  FeedbackOptions,
  FeedbackResult,
  FeedbackType,
} from '../../feedback/index.js';
import { getFeedbackStore, FileFeedbackStore } from '../../feedback/index.js';
import { getAuditLog } from './audit.js';

/**
 * Valid threat categories for validation
 */
const VALID_CATEGORIES: ThreatCategory[] = [
  'purchase',
  'website',
  'destructive',
  'secrets',
  'exfiltration',
];

/**
 * Execute the feedback command
 * 
 * @param options - Feedback command options
 * @param store - Optional feedback store (for testing)
 * @returns Result of the feedback operation
 */
export async function feedbackCommand(
  options: FeedbackOptions,
  store?: FileFeedbackStore
): Promise<FeedbackResult> {
  const feedbackStore = store ?? getFeedbackStore();

  // Ensure store is loaded
  if (!feedbackStore.isLoaded()) {
    await feedbackStore.load();
  }

  // Handle list operation
  if (options.list) {
    return handleList(feedbackStore, options.type);
  }

  // Handle show operation
  if (options.show) {
    return handleShow(feedbackStore, options.show);
  }

  // Handle false positive submission
  if (options.falsePositive) {
    return handleFalsePositive(feedbackStore, options.falsePositive);
  }

  // Handle false negative submission
  if (options.falseNegative) {
    return handleFalseNegative(feedbackStore, options.falseNegative, options.category);
  }

  // No valid operation specified
  return {
    success: false,
    message: 'No operation specified. Use --list, --show, --false-positive, or --false-negative.',
  };
}

/**
 * Handle listing feedback entries
 */
function handleList(store: FileFeedbackStore, type?: FeedbackType): FeedbackResult {
  const entries = type ? store.getByType(type) : store.getAll();

  return {
    success: true,
    message: `Found ${entries.length} feedback ${entries.length === 1 ? 'entry' : 'entries'}`,
    entries,
  };
}

/**
 * Handle showing a specific feedback entry
 */
function handleShow(store: FileFeedbackStore, id: string): FeedbackResult {
  const entry = store.get(id);

  if (!entry) {
    return {
      success: false,
      message: `Feedback entry not found: ${id}`,
    };
  }

  return {
    success: true,
    message: 'Feedback entry found',
    entry,
  };
}

/**
 * Handle false positive submission
 */
function handleFalsePositive(store: FileFeedbackStore, detectionId: string): FeedbackResult {
  // Try to find the detection in the audit log
  const auditLog = getAuditLog();
  const auditEntry = auditLog.find((entry, index) => {
    // Match by index (1-based for user display) or partial timestamp match
    const indexId = `${index + 1}`;
    return indexId === detectionId || 
           entry.timestamp.toISOString().includes(detectionId);
  });

  const entry = store.add({
    type: 'false-positive',
    detectionId,
    detection: auditEntry ? {
      category: auditEntry.category,
      severity: auditEntry.severity,
      reason: auditEntry.reason,
      toolName: auditEntry.toolName,
      toolInput: auditEntry.metadata ?? {},
    } : undefined,
  });

  return {
    success: true,
    message: auditEntry
      ? `False positive reported for detection: ${auditEntry.category} (${auditEntry.reason})`
      : `False positive reported with ID: ${detectionId}`,
    entry,
  };
}

/**
 * Handle false negative submission
 */
function handleFalseNegative(
  store: FileFeedbackStore,
  description: string,
  category?: ThreatCategory
): FeedbackResult {
  // Validate category if provided
  if (category && !VALID_CATEGORIES.includes(category)) {
    return {
      success: false,
      message: `Invalid category: ${category}. Valid categories: ${VALID_CATEGORIES.join(', ')}`,
    };
  }

  const entry = store.add({
    type: 'false-negative',
    description,
    suggestedCategory: category,
  });

  return {
    success: true,
    message: category
      ? `False negative reported in category "${category}": ${description}`
      : `False negative reported: ${description}`,
    entry,
  };
}

/**
 * Format a single feedback entry for display
 */
function formatEntry(entry: FeedbackEntry, detailed = false): string {
  const lines: string[] = [];
  const date = new Date(entry.timestamp);
  const dateStr = date.toISOString().replace('T', ' ').substring(0, 19);

  lines.push(`ID: ${entry.id}`);
  lines.push(`Type: ${entry.type}`);
  lines.push(`Status: ${entry.status}`);
  lines.push(`Date: ${dateStr}`);

  if (entry.type === 'false-positive') {
    lines.push(`Detection ID: ${entry.detectionId ?? '(not specified)'}`);
    if (entry.detection) {
      lines.push(`Category: ${entry.detection.category}`);
      lines.push(`Severity: ${entry.detection.severity}`);
      lines.push(`Reason: ${entry.detection.reason}`);
      if (detailed) {
        lines.push(`Tool: ${entry.detection.toolName}`);
        lines.push(`Input: ${JSON.stringify(entry.detection.toolInput, null, 2)}`);
      }
    }
  } else {
    lines.push(`Description: ${entry.description ?? '(none)'}`);
    if (entry.suggestedCategory) {
      lines.push(`Suggested Category: ${entry.suggestedCategory}`);
    }
  }

  if (entry.notes) {
    lines.push(`Notes: ${entry.notes}`);
  }

  return lines.join('\n');
}

/**
 * Format feedback result for console output
 * 
 * @param result - The feedback result to format
 * @param detailed - Whether to include full details
 * @returns Formatted string for display
 */
export function formatFeedbackResult(result: FeedbackResult, detailed = false): string {
  const lines: string[] = [];

  lines.push('=== Feedback ===');
  lines.push('');

  if (!result.success) {
    lines.push(`Error: ${result.message}`);
    return lines.join('\n');
  }

  // Single entry (add or show)
  if (result.entry) {
    lines.push(result.message);
    lines.push('');
    lines.push(formatEntry(result.entry, detailed));
    return lines.join('\n');
  }

  // List of entries
  if (result.entries !== undefined) {
    lines.push(result.message);
    lines.push('');

    if (result.entries.length === 0) {
      lines.push('No feedback entries found.');
    } else {
      for (const entry of result.entries) {
        lines.push('---');
        lines.push(formatEntry(entry, detailed));
        lines.push('');
      }
    }

    return lines.join('\n');
  }

  // Generic success message
  lines.push(result.message);
  return lines.join('\n');
}

/**
 * Format a brief summary of a feedback entry for list display
 */
export function formatFeedbackSummary(entry: FeedbackEntry): string {
  const date = new Date(entry.timestamp);
  const dateStr = date.toISOString().substring(0, 10);
  const shortId = entry.id.substring(0, 8);

  if (entry.type === 'false-positive') {
    const category = entry.detection?.category ?? 'unknown';
    return `[${shortId}] ${dateStr} FP: ${category} - ${entry.detection?.reason ?? entry.detectionId}`;
  } else {
    const desc = entry.description ?? '(no description)';
    const truncated = desc.length > 50 ? desc.substring(0, 47) + '...' : desc;
    return `[${shortId}] ${dateStr} FN: ${truncated}`;
  }
}

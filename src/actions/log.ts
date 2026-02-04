/**
 * Log Action Handler
 * Handles silent audit logging for tool calls that should be allowed but tracked
 */

import type { ActionContext, ActionHandler, ActionResult, ActionLogger } from './types.js';
import { noOpLogger } from './types.js';

/**
 * Format a threat category for display
 */
function formatCategory(category: string): string {
  const categoryNames: Record<string, string> = {
    purchase: 'Purchase/Payment',
    website: 'Website Access',
    destructive: 'Destructive Command',
    secrets: 'Secrets/PII',
    exfiltration: 'Data Transfer',
  };
  return categoryNames[category] || category;
}

/**
 * Log action handler implementation
 * Allows the action but logs it silently for audit purposes
 */
export class LogHandler implements ActionHandler {
  private logger: ActionLogger;

  constructor(logger: ActionLogger = noOpLogger) {
    this.logger = logger;
  }

  async execute(context: ActionContext): Promise<ActionResult> {
    const { analysis, toolCall } = context;

    // Log the action for audit (silent - no user-visible message)
    if (analysis.primaryDetection) {
      this.logger.info('Action logged for audit', {
        toolName: toolCall.toolName,
        category: analysis.primaryDetection.category,
        severity: analysis.primaryDetection.severity,
        reason: analysis.primaryDetection.reason,
        detectionCount: analysis.detections.length,
        detections: analysis.detections.map((d) => ({
          category: formatCategory(d.category),
          severity: d.severity,
          reason: d.reason,
        })),
      });
    } else {
      this.logger.debug('Action logged for audit (no detections)', {
        toolName: toolCall.toolName,
      });
    }

    // No user-visible message for log action
    return {
      allowed: true,
      logged: true,
    };
  }
}

/**
 * Create a log action handler with the given logger
 */
export function createLogHandler(logger?: ActionLogger): LogHandler {
  return new LogHandler(logger);
}

/**
 * Action Executor
 * Main executor that routes to appropriate action handlers based on analysis results
 */

import type { ActionContext, ActionExecutor, ActionResult, ActionLogger, ActionHandler } from './types.js';
import { noOpLogger, createLogger } from './types.js';
import { createBlockHandler } from './block.js';
import { createConfirmHandler } from './confirm.js';
import { createWarnHandler } from './warn.js';
import { createLogHandler } from './log.js';

/**
 * Configuration for the action executor
 */
export interface ExecutorConfig {
  /** Logger to use for action logging */
  logger?: ActionLogger;
  /** Custom block handler */
  blockHandler?: ActionHandler;
  /** Custom confirm handler */
  confirmHandler?: ActionHandler;
  /** Custom warn handler */
  warnHandler?: ActionHandler;
  /** Custom log handler */
  logHandler?: ActionHandler;
}

/**
 * Default action executor implementation
 */
export class DefaultActionExecutor implements ActionExecutor {
  private logger: ActionLogger;
  private blockHandler: ActionHandler;
  private confirmHandler: ActionHandler;
  private warnHandler: ActionHandler;
  private logHandler: ActionHandler;

  constructor(config: ExecutorConfig = {}) {
    this.logger = config.logger ?? noOpLogger;
    this.blockHandler = config.blockHandler ?? createBlockHandler(this.logger);
    this.confirmHandler = config.confirmHandler ?? createConfirmHandler(this.logger);
    this.warnHandler = config.warnHandler ?? createWarnHandler(this.logger);
    this.logHandler = config.logHandler ?? createLogHandler(this.logger);
  }

  /**
   * Execute the appropriate action based on analysis result
   */
  async execute(context: ActionContext): Promise<ActionResult> {
    const { analysis, config } = context;
    const action = analysis.action;

    // Check if the plugin is disabled
    if (config.global?.enabled === false) {
      this.logger.debug('Plugin disabled, allowing action');
      return {
        allowed: true,
        logged: false,
      };
    }

    // Route to appropriate handler based on action
    switch (action) {
      case 'allow':
        return this.handleAllow(context);
      case 'block':
        return this.handleBlock(context);
      case 'confirm':
        return this.handleConfirm(context);
      case 'warn':
        return this.handleWarn(context);
      case 'log':
        return this.handleLog(context);
      default:
        // Unknown action, log and allow as a safety measure
        this.logger.warn('Unknown action type, defaulting to allow', {
          action: action as string,
        });
        return {
          allowed: true,
          message: `Unknown action type: ${action}`,
          logged: true,
        };
    }
  }

  /**
   * Handle allow action - no detection, pass through
   */
  private async handleAllow(context: ActionContext): Promise<ActionResult> {
    this.logger.debug('Action allowed', {
      toolName: context.toolCall.toolName,
    });

    return {
      allowed: true,
      logged: false,
    };
  }

  /**
   * Handle block action
   */
  private async handleBlock(context: ActionContext): Promise<ActionResult> {
    return this.blockHandler.execute(context);
  }

  /**
   * Handle confirm action
   */
  private async handleConfirm(context: ActionContext): Promise<ActionResult> {
    return this.confirmHandler.execute(context);
  }

  /**
   * Handle warn action
   */
  private async handleWarn(context: ActionContext): Promise<ActionResult> {
    return this.warnHandler.execute(context);
  }

  /**
   * Handle log action
   */
  private async handleLog(context: ActionContext): Promise<ActionResult> {
    return this.logHandler.execute(context);
  }
}

/**
 * Create an action executor with the given configuration
 */
export function createActionExecutor(config?: ExecutorConfig): ActionExecutor {
  return new DefaultActionExecutor(config);
}

/**
 * Create an action executor with default logger based on config log level
 */
export function createDefaultActionExecutor(logLevel: 'debug' | 'info' | 'warn' | 'error' = 'info'): ActionExecutor {
  const logger = createLogger(logLevel);
  return new DefaultActionExecutor({ logger });
}

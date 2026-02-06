/**
 * Tool Result Persist Hook Handler
 *
 * Hook handler that scans tool outputs for secrets/PII, prompt injections,
 * and filters sensitive data before it's persisted.
 */

import type {
  ToolResultContext,
  ToolResultPersistResult,
  ToolResultPersistHandler,
} from '../../index.js';
import type { ClawsecConfig } from '../../config/schema.js';
import type { SecretsDetectionResult } from '../../detectors/secrets/types.js';
import { createSecretsDetector } from '../../detectors/secrets/index.js';
import { scan, sanitize } from '../../sanitization/scanner.js';
import type { ScannerConfig } from '../../sanitization/types.js';
import { filterOutput } from './filter.js';
import { createLogger, type Logger } from '../../utils/logger.js';

/**
 * Options for creating a tool-result-persist handler
 */
export interface ToolResultPersistHandlerOptions {
  /**
   * Whether to enable output filtering (redacting secrets)
   * @default true
   */
  filter?: boolean;
  /**
   * Whether to enable prompt injection scanning
   * @default true
   */
  scanInjections?: boolean;
}

/**
 * Create an allow result with no filtering
 */
function createAllowResult(): ToolResultPersistResult {
  return {
    allow: true,
  };
}

/**
 * Create a block result for detected prompt injections
 */
function createBlockResult(
  redactions: Array<{ type: string; description: string }>
): ToolResultPersistResult {
  return {
    allow: false,
    redactions,
  };
}

/**
 * Create a result with filtered output and redaction info
 */
function createFilteredResult(
  filteredOutput: unknown,
  redactions: Array<{ type: string; description: string }>
): ToolResultPersistResult {
  return {
    allow: true,
    filteredOutput,
    redactions,
  };
}

/**
 * Convert tool output to string for scanning
 */
function outputToString(output: unknown): string | undefined {
  if (typeof output === 'string') {
    return output;
  }
  if (output !== null && output !== undefined) {
    return JSON.stringify(output);
  }
  return undefined;
}

/**
 * Create the tool-result-persist handler
 *
 * This handler runs after a tool executes but before the result is persisted.
 * It scans the output for secrets/PII and prompt injections, then redacts
 * or blocks sensitive data.
 *
 * Flow:
 * 1. Check if plugin is enabled
 * 2. Check if filtering/scanning is enabled
 * 3. Run prompt injection scanner on tool output
 * 4. If injection detected with block action, block the output
 * 5. Run secrets detector on tool output
 * 6. Filter output if secrets detected
 * 7. Return result with filtered output and redaction metadata
 *
 * @param config - Clawsec configuration
 * @param options - Optional handler options
 * @param logger - Optional logger instance
 * @returns ToolResultPersistHandler function
 */
export function createToolResultPersistHandler(
  config: ClawsecConfig,
  options?: ToolResultPersistHandlerOptions,
  logger?: Logger
): ToolResultPersistHandler {
  const log = logger ?? createLogger(null, null);
  const filterEnabled = options?.filter ?? true;
  const scanInjectionsEnabled = options?.scanInjections ?? true;

  // Create secrets detector from config
  const secretsDetector = createSecretsDetector({
    enabled: config.rules?.secrets?.enabled ?? true,
    severity: config.rules?.secrets?.severity ?? 'critical',
    action: config.rules?.secrets?.action ?? 'block',
  }, log);

  // Create scanner config from sanitization rules
  const sanitizationConfig = config.rules?.sanitization;
  const scannerConfig: ScannerConfig = {
    enabled: sanitizationConfig?.enabled ?? true,
    categories: {
      instructionOverride: sanitizationConfig?.categories?.instructionOverride ?? true,
      systemLeak: sanitizationConfig?.categories?.systemLeak ?? true,
      jailbreak: sanitizationConfig?.categories?.jailbreak ?? true,
      encodedPayload: sanitizationConfig?.categories?.encodedPayload ?? true,
    },
    minConfidence: sanitizationConfig?.minConfidence ?? 0.5,
    redactMatches: sanitizationConfig?.redactMatches ?? false,
  };

  return async (context: ToolResultContext): Promise<ToolResultPersistResult> => {
    const toolName = context.toolName;
    log.debug(`[Hook:tool-result-persist] Entry: tool=${toolName}`);

    // 1. Check if plugin is globally disabled
    if (config.global?.enabled === false) {
      log.debug(`[Hook:tool-result-persist] Plugin disabled, allowing output`);
      return createAllowResult();
    }

    // Convert output to string for scanning
    const toolOutputString = outputToString(context.toolOutput);

    // 2. Run prompt injection scanner if enabled
    if (scanInjectionsEnabled && sanitizationConfig?.enabled !== false && toolOutputString) {
      log.debug(`[Hook:tool-result-persist] Scanning for prompt injections`);
      const scanResult = scan(toolOutputString, scannerConfig);

      if (scanResult.hasInjection) {
        const categories = [...new Set(scanResult.matches.map(m => m.category))];
        log.warn(`[Hook:tool-result-persist] Prompt injection detected: categories=${categories.join(',')}, matches=${scanResult.matches.length}`);

        const injectionRedactions = scanResult.matches.map(match => ({
          type: `injection-${match.category}`,
          description: `Prompt injection detected: ${match.match.substring(0, 50)}${match.match.length > 50 ? '...' : ''}`,
        }));

        // If action is 'block', reject the output entirely
        if (sanitizationConfig?.action === 'block') {
          log.info(`[Hook:tool-result-persist] Blocking output due to injection`);
          return createBlockResult(injectionRedactions);
        }

        // If redactMatches is enabled, sanitize the output
        if (sanitizationConfig?.redactMatches) {
          log.info(`[Hook:tool-result-persist] Sanitizing injection patterns`);
          const sanitizedOutput = sanitize(toolOutputString, scanResult.matches);
          return createFilteredResult(sanitizedOutput, injectionRedactions);
        }

        // Otherwise, just log/warn and continue
        // The redactions are passed for logging purposes
      }
    }

    // 3. Check if secrets filtering is disabled
    if (!filterEnabled || config.rules?.secrets?.enabled === false) {
      return createAllowResult();
    }

    // 4. Run secrets detector on the tool output
    log.debug(`[Hook:tool-result-persist] Scanning for secrets`);
    let detections: SecretsDetectionResult[] = [];
    try {
      detections = await secretsDetector.detectAll({
        toolName: context.toolName,
        toolInput: context.toolInput,
        toolOutput: toolOutputString,
      });

      if (detections.length > 0) {
        const types = [...new Set(detections.map(d => d.metadata?.type || 'unknown'))];
        log.info(`[Hook:tool-result-persist] Secrets detected: count=${detections.length}, types=${types.join(',')}`);
      }
    } catch (error) {
      // CRITICAL BUG FIX: Log error instead of silent failure
      const errorMessage = error instanceof Error ? error.message : String(error);
      log.error(`[Hook:tool-result-persist] Error scanning for secrets: ${errorMessage}, allowing unfiltered output`);
      return createAllowResult();
    }

    // 5. Filter output with pattern matching (catches secrets detector might have missed)
    const filterResult = filterOutput(context.toolOutput, detections);

    // 6. If nothing was redacted, allow through unchanged
    if (!filterResult.wasRedacted) {
      log.debug(`[Hook:tool-result-persist] Exit: tool=${toolName}, no filtering needed`);
      return createAllowResult();
    }

    // 7. Return filtered result with redaction metadata
    log.info(`[Hook:tool-result-persist] Exit: tool=${toolName}, redactions=${filterResult.redactions.length}`);
    return createFilteredResult(
      filterResult.filteredOutput,
      filterResult.redactions
    );
  };
}

/**
 * Create a default tool-result-persist handler with default configuration
 */
export function createDefaultToolResultPersistHandler(): ToolResultPersistHandler {
  const defaultConfig: ClawsecConfig = {
    version: '1.0',
    global: {
      enabled: true,
      logLevel: 'info',
    },
    llm: {
      enabled: true,
      model: null,
    },
    rules: {
      purchase: {
        enabled: true,
        severity: 'critical',
        action: 'block',
        spendLimits: { perTransaction: 100, daily: 500 },
        domains: { mode: 'blocklist', blocklist: [] },
      },
      website: {
        enabled: true,
        mode: 'blocklist',
        severity: 'high',
        action: 'block',
        blocklist: [],
        allowlist: [],
      },
      destructive: {
        enabled: true,
        severity: 'critical',
        action: 'confirm',
        shell: { enabled: true },
        cloud: { enabled: true },
        code: { enabled: true },
      },
      secrets: {
        enabled: true,
        severity: 'critical',
        action: 'block',
      },
      exfiltration: {
        enabled: true,
        severity: 'high',
        action: 'block',
      },
      sanitization: {
        enabled: true,
        severity: 'high',
        action: 'block',
        minConfidence: 0.5,
        redactMatches: false,
        categories: {
          instructionOverride: true,
          systemLeak: true,
          jailbreak: true,
          encodedPayload: true,
        },
      },
    },
    approval: {
      native: { enabled: true, timeout: 300 },
      agentConfirm: { enabled: true, parameterName: '_clawsec_confirm' },
      webhook: { enabled: false, url: undefined, timeout: 30, headers: {} },
    },
  };

  return createToolResultPersistHandler(defaultConfig);
}

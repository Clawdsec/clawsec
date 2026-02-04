/**
 * Test Command
 * Tests a specific rule against sample input
 */

import { loadConfig } from '../../config/index.js';
import { createPurchaseDetector } from '../../detectors/purchase/index.js';
import { createWebsiteDetector } from '../../detectors/website/index.js';
import { createDestructiveDetector } from '../../detectors/destructive/index.js';
import { createSecretsDetector } from '../../detectors/secrets/index.js';
import { createExfiltrationDetector } from '../../detectors/exfiltration/index.js';
import type { ThreatCategory } from '../../engine/index.js';
import type { TestResult, CLIOptions } from './types.js';

/** Valid rule names */
const VALID_RULES = ['purchase', 'website', 'destructive', 'secrets', 'exfiltration'] as const;
type RuleName = typeof VALID_RULES[number];

/**
 * Validate that a string is a valid rule name
 */
function isValidRule(rule: string): rule is RuleName {
  return VALID_RULES.includes(rule as RuleName);
}

/**
 * Execute the test command
 * 
 * @param ruleName - Name of the rule to test
 * @param input - JSON input object to test
 * @param options - CLI options including optional config path
 * @returns Test result showing detection status
 */
export async function testCommand(
  ruleName: string,
  input: Record<string, unknown>,
  options: CLIOptions = {}
): Promise<TestResult> {
  // Validate rule name
  if (!isValidRule(ruleName)) {
    throw new Error(
      `Invalid rule: "${ruleName}". Valid rules are: ${VALID_RULES.join(', ')}`
    );
  }

  // Load config
  const config = loadConfig(options.config);

  // Create detection context from input
  const context = {
    toolName: (input.toolName as string) || 'test',
    toolInput: input,
    url: input.url as string | undefined,
    toolOutput: input.toolOutput as string | undefined,
  };

  // Run the appropriate detector
  let result: TestResult;

  switch (ruleName) {
    case 'purchase': {
      const detector = createPurchaseDetector(config.rules.purchase);
      const detection = await detector.detect(context);
      result = {
        detected: detection.detected,
        category: detection.detected ? detection.category as ThreatCategory : undefined,
        severity: detection.detected ? detection.severity : undefined,
        confidence: detection.detected ? detection.confidence : undefined,
        reason: detection.detected ? detection.reason : undefined,
      };
      break;
    }

    case 'website': {
      const detector = createWebsiteDetector(config.rules.website);
      const detection = await detector.detect(context);
      result = {
        detected: detection.detected,
        category: detection.detected ? detection.category as ThreatCategory : undefined,
        severity: detection.detected ? detection.severity : undefined,
        confidence: detection.detected ? detection.confidence : undefined,
        reason: detection.detected ? detection.reason : undefined,
      };
      break;
    }

    case 'destructive': {
      const detector = createDestructiveDetector(config.rules.destructive);
      const detection = await detector.detect(context);
      result = {
        detected: detection.detected,
        category: detection.detected ? detection.category as ThreatCategory : undefined,
        severity: detection.detected ? detection.severity : undefined,
        confidence: detection.detected ? detection.confidence : undefined,
        reason: detection.detected ? detection.reason : undefined,
      };
      break;
    }

    case 'secrets': {
      const detector = createSecretsDetector(config.rules.secrets);
      const detection = await detector.detect(context);
      result = {
        detected: detection.detected,
        category: detection.detected ? detection.category as ThreatCategory : undefined,
        severity: detection.detected ? detection.severity : undefined,
        confidence: detection.detected ? detection.confidence : undefined,
        reason: detection.detected ? detection.reason : undefined,
      };
      break;
    }

    case 'exfiltration': {
      const detector = createExfiltrationDetector(config.rules.exfiltration);
      const detection = await detector.detect(context);
      result = {
        detected: detection.detected,
        category: detection.detected ? detection.category as ThreatCategory : undefined,
        severity: detection.detected ? detection.severity : undefined,
        confidence: detection.detected ? detection.confidence : undefined,
        reason: detection.detected ? detection.reason : undefined,
      };
      break;
    }

    default:
      // Should never reach here due to isValidRule check
      throw new Error(`Unknown rule: ${ruleName}`);
  }

  return result;
}

/**
 * Format test result for console output
 * 
 * @param result - Test result to format
 * @param ruleName - Name of the rule that was tested
 * @returns Formatted string for display
 */
export function formatTestResult(result: TestResult, ruleName: string): string {
  const lines: string[] = [];

  lines.push(`=== Test Result: ${ruleName} ===`);
  lines.push('');

  if (result.detected) {
    lines.push('Status: DETECTED');
    lines.push(`Category: ${result.category}`);
    lines.push(`Severity: ${result.severity}`);
    lines.push(`Confidence: ${((result.confidence || 0) * 100).toFixed(1)}%`);
    lines.push(`Reason: ${result.reason}`);
  } else {
    lines.push('Status: NOT DETECTED');
    lines.push('No threats found for this input.');
  }

  return lines.join('\n');
}

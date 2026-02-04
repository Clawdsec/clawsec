/**
 * Status Command
 * Shows configuration status, enabled rules, and any issues
 */

import * as path from 'node:path';
import {
  loadConfig,
  findConfigFile,
  isValidConfig,
  ConfigLoadError,
} from '../../config/index.js';
import type { StatusResult, CLIOptions } from './types.js';

/** All available rule names */
const ALL_RULES = ['purchase', 'website', 'destructive', 'secrets', 'exfiltration'] as const;

/**
 * Execute the status command
 * 
 * @param options - CLI options including optional config path
 * @returns Status result with config info and rule status
 */
export async function statusCommand(options: CLIOptions = {}): Promise<StatusResult> {
  const issues: string[] = [];
  let configPath = options.config || '';
  let configValid = false;
  const enabledRules: string[] = [];
  const disabledRules: string[] = [];

  // Find config file if not specified
  if (!configPath) {
    const foundPath = findConfigFile();
    if (foundPath) {
      configPath = foundPath;
    } else {
      configPath = '(none - using defaults)';
    }
  } else {
    configPath = path.resolve(configPath);
  }

  try {
    // Load and validate config
    const config = loadConfig(options.config);
    
    // Check if config is valid
    const validation = isValidConfig(config);
    configValid = validation.valid;
    
    if (!validation.valid) {
      issues.push(...validation.errors.map(e => `${e.path}: ${e.message}`));
    }

    // Check global enabled status
    if (!config.global.enabled) {
      issues.push('Plugin is globally disabled');
    }

    // Check each rule's status
    for (const ruleName of ALL_RULES) {
      const rule = config.rules[ruleName];
      if (rule && rule.enabled) {
        enabledRules.push(ruleName);
      } else {
        disabledRules.push(ruleName);
      }
    }

    // Additional validation checks
    if (config.rules.website.mode === 'allowlist' && config.rules.website.allowlist.length === 0) {
      issues.push('Website rule is in allowlist mode but allowlist is empty (blocks all sites)');
    }

    if (config.approval.webhook?.enabled && !config.approval.webhook.url) {
      issues.push('Webhook approval is enabled but no URL is configured');
    }

  } catch (error) {
    configValid = false;
    if (error instanceof ConfigLoadError) {
      issues.push(`Failed to load config: ${error.message}`);
    } else if (error instanceof Error) {
      issues.push(`Configuration error: ${error.message}`);
    } else {
      issues.push('Unknown configuration error');
    }
    
    // If config failed to load, mark all rules as unknown
    disabledRules.push(...ALL_RULES);
  }

  return {
    configPath,
    configValid,
    enabledRules,
    disabledRules,
    issues,
  };
}

/**
 * Format status result for console output
 * 
 * @param result - Status result to format
 * @returns Formatted string for display
 */
export function formatStatusResult(result: StatusResult): string {
  const lines: string[] = [];

  lines.push('=== Clawsec Status ===');
  lines.push('');
  lines.push(`Config File: ${result.configPath}`);
  lines.push(`Config Valid: ${result.configValid ? 'Yes' : 'No'}`);
  lines.push('');

  if (result.enabledRules.length > 0) {
    lines.push('Enabled Rules:');
    for (const rule of result.enabledRules) {
      lines.push(`  - ${rule}`);
    }
  }

  if (result.disabledRules.length > 0) {
    lines.push('');
    lines.push('Disabled Rules:');
    for (const rule of result.disabledRules) {
      lines.push(`  - ${rule}`);
    }
  }

  if (result.issues.length > 0) {
    lines.push('');
    lines.push('Issues:');
    for (const issue of result.issues) {
      lines.push(`  ! ${issue}`);
    }
  }

  return lines.join('\n');
}

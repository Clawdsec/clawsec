/**
 * Clawsec CLI Entry Point
 * Command line interface for interacting with Clawsec
 */

import {
  statusCommand,
  formatStatusResult,
  testCommand,
  formatTestResult,
  auditCommand,
  formatAuditResult,
} from './commands/index.js';
import type { CLIOptions, AuditOptions } from './commands/index.js';
import type { ThreatCategory } from '../engine/index.js';

// Re-export commands and types
export * from './commands/index.js';

/**
 * Show CLI help message
 */
function showHelp(): void {
  console.log(`
Clawsec CLI - Security plugin for OpenClaw.ai

Usage: clawsec <command> [options]

Commands:
  status                  Show configuration status and enabled rules
  test                    Test a rule against sample input
  audit                   View audit log of detections

Options:
  --config <path>         Path to clawsec.yaml config file
  --help, -h              Show this help message

Command: status
  Check configuration status and show enabled/disabled rules.
  
  Example:
    clawsec status
    clawsec status --config ./my-config.yaml

Command: test
  Test a specific rule against JSON input.
  
  Options:
    --rule <name>         Rule to test (purchase, website, destructive, secrets, exfiltration)
    --input <json>        JSON input to test against
  
  Examples:
    clawsec test --rule purchase --input '{"url":"https://amazon.com/checkout"}'
    clawsec test --rule destructive --input '{"command":"rm -rf /"}'
    clawsec test --rule secrets --input '{"content":"api_key=sk-abc123"}'

Command: audit
  View the audit log of recent detections.
  
  Options:
    --limit <n>           Maximum number of entries to show (default: 10)
    --category <cat>      Filter by category (purchase, website, destructive, secrets, exfiltration)
  
  Examples:
    clawsec audit
    clawsec audit --limit 20
    clawsec audit --category secrets
`);
}

/**
 * Parse command line arguments
 */
interface ParsedArgs {
  command: string | null;
  options: Record<string, string | boolean>;
}

function parseArgs(args: string[]): ParsedArgs {
  const result: ParsedArgs = {
    command: null,
    options: {},
  };

  let i = 0;
  
  // First non-option argument is the command
  while (i < args.length) {
    const arg = args[i];
    
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const nextArg = args[i + 1];
      
      // Check if next arg is a value or another option
      if (nextArg && !nextArg.startsWith('--') && !nextArg.startsWith('-')) {
        result.options[key] = nextArg;
        i += 2;
      } else {
        result.options[key] = true;
        i++;
      }
    } else if (arg.startsWith('-')) {
      // Short option
      const key = arg.slice(1);
      result.options[key] = true;
      i++;
    } else if (!result.command) {
      result.command = arg;
      i++;
    } else {
      // Skip unknown positional arguments
      i++;
    }
  }

  return result;
}

/**
 * Run the CLI
 * 
 * @param args - Command line arguments (without node and script path)
 * @returns Exit code (0 for success, 1 for error)
 */
export async function runCLI(args: string[]): Promise<number> {
  const parsed = parseArgs(args);
  
  // Check for help flag
  if (parsed.options.help || parsed.options.h) {
    showHelp();
    return 0;
  }

  // No command provided
  if (!parsed.command) {
    console.error('Error: No command specified.\n');
    showHelp();
    return 1;
  }

  // Build CLI options
  const cliOptions: CLIOptions = {};
  if (typeof parsed.options.config === 'string') {
    cliOptions.config = parsed.options.config;
  }

  try {
    switch (parsed.command) {
      case 'status': {
        const result = await statusCommand(cliOptions);
        console.log(formatStatusResult(result));
        return result.configValid && result.issues.length === 0 ? 0 : 1;
      }

      case 'test': {
        // Validate required options
        const ruleName = parsed.options.rule;
        const inputJson = parsed.options.input;

        if (typeof ruleName !== 'string') {
          console.error('Error: --rule is required for test command');
          console.error('Example: clawsec test --rule purchase --input \'{"url":"https://example.com"}\'');
          return 1;
        }

        if (typeof inputJson !== 'string') {
          console.error('Error: --input is required for test command');
          console.error('Example: clawsec test --rule purchase --input \'{"url":"https://example.com"}\'');
          return 1;
        }

        // Parse JSON input
        let input: Record<string, unknown>;
        try {
          input = JSON.parse(inputJson);
        } catch {
          console.error('Error: Invalid JSON input');
          console.error(`Received: ${inputJson}`);
          return 1;
        }

        const result = await testCommand(ruleName, input, cliOptions);
        console.log(formatTestResult(result, ruleName));
        return result.detected ? 1 : 0;
      }

      case 'audit': {
        const auditOptions: AuditOptions = {};
        
        // Parse limit
        if (typeof parsed.options.limit === 'string') {
          const limit = parseInt(parsed.options.limit, 10);
          if (isNaN(limit) || limit < 1) {
            console.error('Error: --limit must be a positive integer');
            return 1;
          }
          auditOptions.limit = limit;
        }

        // Parse category
        if (typeof parsed.options.category === 'string') {
          const validCategories = ['purchase', 'website', 'destructive', 'secrets', 'exfiltration'];
          if (!validCategories.includes(parsed.options.category)) {
            console.error(`Error: Invalid category "${parsed.options.category}"`);
            console.error(`Valid categories: ${validCategories.join(', ')}`);
            return 1;
          }
          auditOptions.category = parsed.options.category as ThreatCategory;
        }

        const result = await auditCommand(auditOptions);
        console.log(formatAuditResult(result, auditOptions));
        return 0;
      }

      default:
        console.error(`Error: Unknown command "${parsed.command}"`);
        showHelp();
        return 1;
    }
  } catch (error) {
    if (error instanceof Error) {
      console.error(`Error: ${error.message}`);
    } else {
      console.error('An unknown error occurred');
    }
    return 1;
  }
}

/**
 * Main entry point when run directly
 */
export async function main(): Promise<void> {
  // Remove 'node' and script path from arguments
  const args = process.argv.slice(2);
  const exitCode = await runCLI(args);
  process.exit(exitCode);
}

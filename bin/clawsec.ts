#!/usr/bin/env node
/**
 * Clawsec CLI Executable
 * Entry point for the clawsec command line tool
 */

import { main } from '../src/cli/index.js';

// Run the CLI
main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

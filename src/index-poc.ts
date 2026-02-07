/**
 * POC: Minimal Clawsec Plugin for Testing Hook Persistence
 *
 * This is Step 1 of the debug plan: Inline handler with NO state, NO closures.
 *
 * Purpose: Verify that hooks execute on BOTH first and second activation.
 *
 * To test next steps, uncomment the relevant section below.
 *
 * CRITICAL: Uses production logger utility for visibility in OpenClaw service logs
 */

import type { OpenClawPluginAPI, ToolCallContext, BeforeToolCallResult } from './index.js';
import { createLogger } from './utils/logger.js';

// =============================================================================
// STEP 1: MINIMAL INLINE HANDLER (CURRENTLY ACTIVE)
// =============================================================================

export default {
  id: 'clawsec-poc',
  name: 'Clawsec POC',

  register(api: OpenClawPluginAPI) {
    // Create logger using production utility - logs visible in OpenClaw service
    const logger = createLogger(api, api.config);

    const separator = '='.repeat(80);

    logger.info(separator);
    logger.info('[POC STEP 1] 📝 REGISTRATION PHASE - register() called');
    logger.info(`[POC STEP 1] Timestamp: ${new Date().toISOString()}`);
    logger.info(`[POC STEP 1] API available: ${!!api}`);
    logger.info(`[POC STEP 1] registerHook available: ${typeof api.registerHook}`);
    logger.info(separator);

    // Register hook with INLINE handler (no closure, no state)
    // ⚠️ NOTE: logger is captured in closure from parent scope
    api.registerHook(
      'before-tool-call',
      async (context: ToolCallContext): Promise<BeforeToolCallResult> => {
        // ⚠️ THIS CODE RUNS AT EXECUTION TIME (when tool is called)
        const execSeparator = '━'.repeat(80);

        logger.info(execSeparator);
        logger.info('[POC STEP 1] ✅ EXECUTION PHASE - Hook TRIGGERED!');
        logger.info(`[POC STEP 1] Tool name: ${context.toolName}`);
        logger.info(`[POC STEP 1] Execution timestamp: ${new Date().toISOString()}`);
        logger.info(`[POC STEP 1] Session: ${context.sessionId}`);
        logger.info(execSeparator);

        // Always allow - this is just testing if hooks execute
        return { allow: true };
      },
      {
        id: 'clawsec-poc-hook-step1',
        name: 'POC Step 1: Inline Handler',
        priority: 100,
        enabled: true
      }
    );

    logger.info('[POC STEP 1] ✓ Hook registered with ID: clawsec-poc-hook-step1');
    logger.info('[POC STEP 1] Waiting for tool calls to trigger hook...');
  }
};

// =============================================================================
// STEP 2: HANDLER FACTORY (UNCOMMENT TO TEST)
// =============================================================================

/*
import { createLogger, type Logger } from './utils/logger.js';

function createHandler(logger: Logger) {
  const createdAt = Date.now();
  const createdTimestamp = new Date().toISOString();

  logger.info('[POC STEP 2] Handler factory called');
  logger.info(`[POC STEP 2] Factory timestamp: ${createdTimestamp}`);
  logger.info('[POC STEP 2] Creating handler closure...');

  return async (context: ToolCallContext): Promise<BeforeToolCallResult> => {
    // ⚠️ THIS CODE RUNS AT EXECUTION TIME (when tool is called)
    const execSeparator = '━'.repeat(80);

    logger.info(execSeparator);
    logger.info('[POC STEP 2] ✅ EXECUTION PHASE - Hook TRIGGERED!');
    logger.info(`[POC STEP 2] Handler was created at: ${createdTimestamp}`);
    logger.info(`[POC STEP 2] Handler age: ${Date.now() - createdAt}ms`);
    logger.info(`[POC STEP 2] Tool name: ${context.toolName}`);
    logger.info(`[POC STEP 2] Execution timestamp: ${new Date().toISOString()}`);
    logger.info(execSeparator);

    return { allow: true };
  };
}

export default {
  id: 'clawsec-poc',
  name: 'Clawsec POC',

  register(api: OpenClawPluginAPI) {
    const logger = createLogger(api, api.config);
    const separator = '='.repeat(80);

    logger.info(separator);
    logger.info('[POC STEP 2] 📝 REGISTRATION PHASE - register() called');
    logger.info(`[POC STEP 2] Timestamp: ${new Date().toISOString()}`);
    logger.info(separator);

    const handler = createHandler(logger);  // Create closure

    api.registerHook('before-tool-call', handler, {
      id: 'clawsec-poc-hook-step2',
      name: 'POC Step 2: Handler Factory',
      priority: 100,
      enabled: true
    });

    logger.info('[POC STEP 2] ✓ Hook registered with ID: clawsec-poc-hook-step2');
    logger.info('[POC STEP 2] Waiting for tool calls to trigger hook...');
  }
};
*/

// =============================================================================
// STEP 3: MODULE STATE (UNCOMMENT TO TEST)
// =============================================================================

/*
import { createLogger } from './utils/logger.js';

let activationCount = 0;
let lastActivationTime: string | null = null;

export default {
  id: 'clawsec-poc',
  name: 'Clawsec POC',

  register(api: OpenClawPluginAPI) {
    const logger = createLogger(api, api.config);

    activationCount++;
    lastActivationTime = new Date().toISOString();

    const separator = '='.repeat(80);

    logger.info(separator);
    logger.info('[POC STEP 3] 📝 REGISTRATION PHASE - register() called');
    logger.info(`[POC STEP 3] Module activation count: ${activationCount}`);
    logger.info(`[POC STEP 3] Last activation timestamp: ${lastActivationTime}`);
    logger.info(separator);

    const currentActivation = activationCount;

    const handler = async (context: ToolCallContext): Promise<BeforeToolCallResult> => {
      // ⚠️ THIS CODE RUNS AT EXECUTION TIME (when tool is called)
      const execSeparator = '━'.repeat(80);

      logger.info(execSeparator);
      logger.info('[POC STEP 3] ✅ EXECUTION PHASE - Hook TRIGGERED!');
      logger.info(`[POC STEP 3] Captured activation number: ${currentActivation}`);
      logger.info(`[POC STEP 3] Current module activation count: ${activationCount}`);
      logger.info(`[POC STEP 3] Tool name: ${context.toolName}`);
      logger.info(`[POC STEP 3] Execution timestamp: ${new Date().toISOString()}`);
      logger.info(execSeparator);

      return { allow: true };
    };

    api.registerHook('before-tool-call', handler, {
      id: 'clawsec-poc-hook-step3',
      name: 'POC Step 3: Module State',
      priority: 100,
      enabled: true
    });

    logger.info('[POC STEP 3] ✓ Hook registered with ID: clawsec-poc-hook-step3');
    logger.info('[POC STEP 3] Waiting for tool calls to trigger hook...');
  }
};
*/

// =============================================================================
// STEP 4: ACTIVATE/DEACTIVATE PATTERN (UNCOMMENT TO TEST)
// =============================================================================

/*
import { createLogger, type Logger } from './utils/logger.js';

const state = {
  initialized: false,
  handlerId: null as string | null,
  activationTime: null as string | null,
  activationCount: 0
};

// Module-level logger - will be set in activate()
let logger: Logger;

function activate(api: OpenClawPluginAPI) {
  logger = createLogger(api, api.config);

  state.activationCount++;

  const separator = '='.repeat(80);

  logger.info(separator);
  logger.info('[POC STEP 4] 📝 REGISTRATION PHASE - activate() called');
  logger.info(`[POC STEP 4] state.initialized before: ${state.initialized}`);
  logger.info(`[POC STEP 4] state.activationCount: ${state.activationCount}`);
  logger.info(`[POC STEP 4] Timestamp: ${new Date().toISOString()}`);
  logger.info(separator);

  if (state.initialized) {
    logger.warn('[POC STEP 4] ⚠️  Already initialized, SKIPPING hook registration!');
    logger.warn('[POC STEP 4] This means hook will NOT be registered on this activation');
    return;
  }

  state.activationTime = new Date().toISOString();

  const handler = async (context: ToolCallContext): Promise<BeforeToolCallResult> => {
    // ⚠️ THIS CODE RUNS AT EXECUTION TIME (when tool is called)
    const execSeparator = '━'.repeat(80);

    logger.info(execSeparator);
    logger.info('[POC STEP 4] ✅ EXECUTION PHASE - Hook TRIGGERED!');
    logger.info(`[POC STEP 4] Handler from activation: ${state.activationTime}`);
    logger.info(`[POC STEP 4] Total activations seen: ${state.activationCount}`);
    logger.info(`[POC STEP 4] Tool name: ${context.toolName}`);
    logger.info(`[POC STEP 4] Execution timestamp: ${new Date().toISOString()}`);
    logger.info(execSeparator);

    return { allow: true };
  };

  state.handlerId = 'clawsec-poc-hook-step4';

  api.registerHook('before-tool-call', handler, {
    id: state.handlerId,
    name: 'POC Step 4: Activate/Deactivate',
    priority: 100,
    enabled: true
  });

  state.initialized = true;
  logger.info(`[POC STEP 4] ✓ Hook registered with ID: ${state.handlerId}`);
  logger.info(`[POC STEP 4] state.initialized now: ${state.initialized}`);
  logger.info('[POC STEP 4] Waiting for tool calls to trigger hook...');
}

function deactivate(api: OpenClawPluginAPI) {
  if (!logger) {
    logger = createLogger(api, api.config);
  }

  const separator = '='.repeat(80);

  logger.info(separator);
  logger.info('[POC STEP 4] 🧹 DEACTIVATION - deactivate() called');
  logger.info(`[POC STEP 4] state.initialized: ${state.initialized}`);
  logger.info(`[POC STEP 4] Timestamp: ${new Date().toISOString()}`);
  logger.info(separator);

  if (!state.initialized) {
    logger.info('[POC STEP 4] Not initialized, nothing to clean up');
    return;
  }

  if (state.handlerId) {
    logger.info(`[POC STEP 4] Unregistering hook: ${state.handlerId}`);
    api.unregisterHook('before-tool-call', state.handlerId);
  }

  state.initialized = false;
  state.handlerId = null;
  state.activationTime = null;
  // Note: We intentionally DON'T reset activationCount to test persistence

  logger.info(`[POC STEP 4] Cleanup complete, state.initialized reset to: ${state.initialized}`);
  logger.info(`[POC STEP 4] (activationCount NOT reset, still: ${state.activationCount})`);
}

export default {
  id: 'clawsec-poc',
  name: 'Clawsec POC',

  register(api: OpenClawPluginAPI) {
    logger = createLogger(api, api.config);
    logger.info('[POC STEP 4] 🚀 register() called, delegating to activate()...');
    activate(api);
  },

  activate,
  deactivate
};
*/

// =============================================================================
// TESTING NOTES
// =============================================================================

/*
After each step, test:
1. Build: npm run build:poc
2. Install: openclaw plugins install -l ./
3. First activation: Trigger a tool call, verify logs appear
4. Restart OpenClaw (SIGTERM or restart command)
5. Second activation: Trigger another tool call
6. Check if logs STILL appear

Document results in POC-RESULTS.md:
- Which step works on second activation?
- Which step breaks?
- What's the last log message you see?
- Does the hook ID change between activations?
*/

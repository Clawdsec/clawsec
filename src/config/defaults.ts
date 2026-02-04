/**
 * Clawsec Default Configuration
 * Sensible default values for the security plugin
 */

import type { ClawsecConfig } from './schema.js';

/**
 * Default configuration for Clawsec
 *
 * All features enabled by default with conservative settings:
 * - Purchases are blocked by default
 * - Destructive commands require confirmation
 * - Secrets and exfiltration are blocked
 */
export const defaultConfig: ClawsecConfig = {
  version: '1.0',

  global: {
    enabled: true,
    logLevel: 'info',
  },

  llm: {
    enabled: true,
    model: null, // Use OpenClaw's configured model
  },

  rules: {
    purchase: {
      enabled: true,
      severity: 'critical',
      action: 'block',
      spendLimits: {
        perTransaction: 100,
        daily: 500,
      },
      domains: {
        mode: 'blocklist',
        blocklist: [
          'amazon.com',
          'stripe.com',
          'paypal.com',
          'checkout.stripe.com',
          'buy.stripe.com',
          'billing.stripe.com',
        ],
      },
    },

    website: {
      enabled: true,
      mode: 'blocklist',
      severity: 'high',
      action: 'block',
      blocklist: [
        '*.malware.com',
        'phishing-*.com',
        '*.darkweb.*',
      ],
      allowlist: [
        'docs.openclaw.ai',
        'github.com',
        'stackoverflow.com',
        'developer.mozilla.org',
      ],
    },

    destructive: {
      enabled: true,
      severity: 'critical',
      action: 'confirm',
      shell: {
        enabled: true,
      },
      cloud: {
        enabled: true,
      },
      code: {
        enabled: true,
      },
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
    native: {
      enabled: true,
      timeout: 300, // 5 minutes
    },
    agentConfirm: {
      enabled: true,
      parameterName: '_clawsec_confirm',
    },
    webhook: {
      enabled: false,
      url: undefined,
      timeout: 30,
      headers: {},
    },
  },
};

/**
 * Returns a deep clone of the default configuration
 * to prevent accidental mutations
 */
export function getDefaultConfig(): ClawsecConfig {
  return structuredClone(defaultConfig);
}

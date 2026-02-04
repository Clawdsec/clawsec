/**
 * Tests for Clawsec Configuration Module
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  // Schema
  ClawsecConfigSchema,
  SeveritySchema,
  ActionSchema,
  LogLevelSchema,
  FilterModeSchema,
  type ClawsecConfig,
  type PartialClawsecConfig,
  // Defaults
  defaultConfig,
  getDefaultConfig,
  // Loader
  validateConfig,
  isValidConfig,
  mergeWithDefaults,
  mergeConfigs,
  loadConfig,
  loadConfigFromString,
  findConfigFile,
  ConfigValidationError,
  ConfigLoadError,
} from './index.js';

// =============================================================================
// TEST FIXTURES
// =============================================================================

let tempDir: string;

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'clawsec-test-'));
}

function writeTempConfig(content: string, fileName: string = 'clawsec.yaml'): string {
  const filePath = path.join(tempDir, fileName);
  fs.writeFileSync(filePath, content, 'utf-8');
  return filePath;
}

// =============================================================================
// ENUM SCHEMA TESTS
// =============================================================================

describe('Enum Schemas', () => {
  describe('SeveritySchema', () => {
    it('should accept valid severity levels', () => {
      expect(SeveritySchema.parse('critical')).toBe('critical');
      expect(SeveritySchema.parse('high')).toBe('high');
      expect(SeveritySchema.parse('medium')).toBe('medium');
      expect(SeveritySchema.parse('low')).toBe('low');
    });

    it('should reject invalid severity levels', () => {
      expect(() => SeveritySchema.parse('invalid')).toThrow();
      expect(() => SeveritySchema.parse('')).toThrow();
      expect(() => SeveritySchema.parse(123)).toThrow();
    });
  });

  describe('ActionSchema', () => {
    it('should accept valid actions', () => {
      expect(ActionSchema.parse('block')).toBe('block');
      expect(ActionSchema.parse('confirm')).toBe('confirm');
      expect(ActionSchema.parse('agent-confirm')).toBe('agent-confirm');
      expect(ActionSchema.parse('warn')).toBe('warn');
      expect(ActionSchema.parse('log')).toBe('log');
    });

    it('should reject invalid actions', () => {
      expect(() => ActionSchema.parse('invalid')).toThrow();
      expect(() => ActionSchema.parse('BLOCK')).toThrow();
    });
  });

  describe('LogLevelSchema', () => {
    it('should accept valid log levels', () => {
      expect(LogLevelSchema.parse('debug')).toBe('debug');
      expect(LogLevelSchema.parse('info')).toBe('info');
      expect(LogLevelSchema.parse('warn')).toBe('warn');
      expect(LogLevelSchema.parse('error')).toBe('error');
    });
  });

  describe('FilterModeSchema', () => {
    it('should accept valid filter modes', () => {
      expect(FilterModeSchema.parse('blocklist')).toBe('blocklist');
      expect(FilterModeSchema.parse('allowlist')).toBe('allowlist');
    });
  });
});

// =============================================================================
// CONFIG SCHEMA TESTS
// =============================================================================

describe('ClawsecConfigSchema', () => {
  it('should parse a complete valid configuration', () => {
    const config = {
      version: '1.0',
      global: {
        enabled: true,
        logLevel: 'debug',
      },
      llm: {
        enabled: true,
        model: 'gpt-4',
      },
      rules: {
        purchase: {
          enabled: true,
          severity: 'critical',
          action: 'block',
          spendLimits: {
            perTransaction: 50,
            daily: 200,
          },
          domains: {
            mode: 'blocklist',
            blocklist: ['amazon.com'],
          },
        },
        website: {
          enabled: true,
          mode: 'allowlist',
          severity: 'high',
          action: 'warn',
          blocklist: ['*.malware.com'],
          allowlist: ['github.com'],
        },
        destructive: {
          enabled: true,
          severity: 'critical',
          action: 'confirm',
          shell: { enabled: true },
          cloud: { enabled: false },
          code: { enabled: true },
        },
        secrets: {
          enabled: true,
          severity: 'critical',
          action: 'block',
        },
        exfiltration: {
          enabled: false,
          severity: 'medium',
          action: 'log',
        },
      },
      approval: {
        native: {
          enabled: true,
          timeout: 600,
        },
        agentConfirm: {
          enabled: true,
          parameterName: '_confirm',
        },
        webhook: {
          enabled: true,
          url: 'https://api.example.com/approve',
          timeout: 60,
          headers: { 'X-API-Key': 'secret' },
        },
      },
    };

    const result = ClawsecConfigSchema.parse(config);
    expect(result.version).toBe('1.0');
    expect(result.global.logLevel).toBe('debug');
    expect(result.llm.model).toBe('gpt-4');
    expect(result.rules.purchase.spendLimits.perTransaction).toBe(50);
    expect(result.rules.website.mode).toBe('allowlist');
    expect(result.rules.destructive.cloud.enabled).toBe(false);
    expect(result.approval.webhook.url).toBe('https://api.example.com/approve');
  });

  it('should apply defaults for missing fields', () => {
    const config = {};
    const result = ClawsecConfigSchema.parse(config);

    expect(result.version).toBe('1.0');
    expect(result.global.enabled).toBe(true);
    expect(result.global.logLevel).toBe('info');
    expect(result.llm.enabled).toBe(true);
    expect(result.llm.model).toBeNull();
    expect(result.rules.purchase.enabled).toBe(true);
    expect(result.rules.purchase.severity).toBe('critical');
    expect(result.rules.purchase.action).toBe('block');
    expect(result.rules.destructive.action).toBe('confirm');
    expect(result.approval.native.timeout).toBe(300);
  });

  it('should reject invalid configurations', () => {
    const invalidConfigs = [
      { global: { logLevel: 'invalid' } },
      { rules: { purchase: { severity: 'ultra' } } },
      { rules: { purchase: { action: 'destroy' } } },
      { rules: { purchase: { spendLimits: { perTransaction: -100 } } } },
      { approval: { webhook: { url: 'not-a-url' } } },
      { approval: { native: { timeout: -1 } } },
    ];

    for (const config of invalidConfigs) {
      expect(() => ClawsecConfigSchema.parse(config)).toThrow();
    }
  });

  it('should handle partial configurations correctly', () => {
    const partial = {
      rules: {
        purchase: {
          enabled: false,
        },
      },
    };

    const result = ClawsecConfigSchema.parse(partial);
    expect(result.rules.purchase.enabled).toBe(false);
    // Other purchase fields should have defaults
    expect(result.rules.purchase.severity).toBe('critical');
    expect(result.rules.purchase.action).toBe('block');
    // Other rules should have defaults
    expect(result.rules.website.enabled).toBe(true);
  });
});

// =============================================================================
// DEFAULT CONFIG TESTS
// =============================================================================

describe('Default Configuration', () => {
  it('should have valid default configuration', () => {
    expect(() => ClawsecConfigSchema.parse(defaultConfig)).not.toThrow();
  });

  it('should enable all protections by default', () => {
    expect(defaultConfig.global.enabled).toBe(true);
    expect(defaultConfig.rules.purchase.enabled).toBe(true);
    expect(defaultConfig.rules.website.enabled).toBe(true);
    expect(defaultConfig.rules.destructive.enabled).toBe(true);
    expect(defaultConfig.rules.secrets.enabled).toBe(true);
    expect(defaultConfig.rules.exfiltration.enabled).toBe(true);
  });

  it('should have conservative default actions', () => {
    expect(defaultConfig.rules.purchase.action).toBe('block');
    expect(defaultConfig.rules.destructive.action).toBe('confirm');
    expect(defaultConfig.rules.secrets.action).toBe('block');
    expect(defaultConfig.rules.exfiltration.action).toBe('block');
  });

  it('should include default blocklists', () => {
    expect(defaultConfig.rules.purchase.domains.blocklist).toContain('amazon.com');
    expect(defaultConfig.rules.purchase.domains.blocklist).toContain('stripe.com');
    expect(defaultConfig.rules.website.blocklist).toContain('*.malware.com');
  });

  it('getDefaultConfig should return a deep clone', () => {
    const config1 = getDefaultConfig();
    const config2 = getDefaultConfig();

    // Should be equal
    expect(config1).toEqual(config2);

    // But not the same object
    expect(config1).not.toBe(config2);

    // Mutations should not affect the original
    config1.rules.purchase.enabled = false;
    expect(config2.rules.purchase.enabled).toBe(true);
    expect(defaultConfig.rules.purchase.enabled).toBe(true);
  });
});

// =============================================================================
// VALIDATION TESTS
// =============================================================================

describe('validateConfig', () => {
  it('should return validated config for valid input', () => {
    const config = validateConfig({
      version: '2.0',
      global: { enabled: false },
    });

    expect(config.version).toBe('2.0');
    expect(config.global.enabled).toBe(false);
    expect(config.global.logLevel).toBe('info'); // default
  });

  it('should throw ConfigValidationError for invalid input', () => {
    expect(() => validateConfig({ global: { logLevel: 'invalid' } })).toThrow(ConfigValidationError);
  });

  it('should provide detailed error messages', () => {
    try {
      validateConfig({
        global: { logLevel: 'invalid' },
        rules: { purchase: { spendLimits: { perTransaction: -100 } } },
      });
      expect.fail('Should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigValidationError);
      const validationError = error as ConfigValidationError;
      expect(validationError.errors.length).toBeGreaterThan(0);
      expect(validationError.message).toContain('Configuration validation failed');
    }
  });
});

describe('isValidConfig', () => {
  it('should return valid: true for valid config', () => {
    const result = isValidConfig({ version: '1.0' });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.config.version).toBe('1.0');
    }
  });

  it('should return valid: false with errors for invalid config', () => {
    const result = isValidConfig({ global: { logLevel: 'invalid' } });
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0].path).toContain('global');
    }
  });
});

// =============================================================================
// MERGING TESTS
// =============================================================================

describe('mergeWithDefaults', () => {
  it('should merge partial config with defaults', () => {
    const partial: PartialClawsecConfig = {
      rules: {
        purchase: {
          enabled: false,
        },
      },
    };

    const result = mergeWithDefaults(partial);
    expect(result.rules.purchase.enabled).toBe(false);
    expect(result.rules.purchase.severity).toBe('critical'); // default
    expect(result.rules.website.enabled).toBe(true); // default
  });

  it('should override nested defaults', () => {
    const partial: PartialClawsecConfig = {
      rules: {
        purchase: {
          spendLimits: {
            perTransaction: 50,
          },
        },
      },
    };

    const result = mergeWithDefaults(partial);
    expect(result.rules.purchase.spendLimits.perTransaction).toBe(50);
    expect(result.rules.purchase.spendLimits.daily).toBe(500); // default
  });
});

describe('mergeConfigs', () => {
  it('should merge multiple configs in order', () => {
    const base: PartialClawsecConfig = {
      version: '1.0',
      global: { enabled: true, logLevel: 'info' },
    };

    const override: PartialClawsecConfig = {
      global: { logLevel: 'debug' },
      rules: { purchase: { enabled: false } },
    };

    const result = mergeConfigs(base, override);
    expect(result.version).toBe('1.0');
    expect(result.global.enabled).toBe(true);
    expect(result.global.logLevel).toBe('debug');
    expect(result.rules.purchase.enabled).toBe(false);
  });

  it('should handle empty configs', () => {
    const result = mergeConfigs({}, {});
    expect(result).toBeDefined();
    expect(result.global.enabled).toBe(true); // default
  });

  it('should merge arrays by replacement, not concatenation', () => {
    const base: PartialClawsecConfig = {
      rules: {
        website: {
          blocklist: ['a.com', 'b.com'],
        },
      },
    };

    const override: PartialClawsecConfig = {
      rules: {
        website: {
          blocklist: ['c.com'],
        },
      },
    };

    const result = mergeConfigs(base, override);
    expect(result.rules.website.blocklist).toEqual(['c.com']);
  });
});

// =============================================================================
// FILE LOADING TESTS
// =============================================================================

describe('loadConfig', () => {
  beforeEach(() => {
    tempDir = createTempDir();
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('should load config from explicit path', () => {
    const configContent = `
version: "2.0"
global:
  enabled: false
  logLevel: debug
rules:
  purchase:
    enabled: false
    severity: high
`;
    const configPath = writeTempConfig(configContent);
    const config = loadConfig(configPath);

    expect(config.version).toBe('2.0');
    expect(config.global.enabled).toBe(false);
    expect(config.global.logLevel).toBe('debug');
    expect(config.rules.purchase.enabled).toBe(false);
    expect(config.rules.purchase.severity).toBe('high');
  });

  it('should load config from .yml extension', () => {
    const configContent = `
version: "1.5"
`;
    const configPath = writeTempConfig(configContent, 'clawsec.yml');
    const config = loadConfig(configPath);

    expect(config.version).toBe('1.5');
  });

  it('should return defaults when no config file found', () => {
    const emptyDir = createTempDir();
    const originalCwd = process.cwd();
    process.chdir(emptyDir);

    try {
      const config = loadConfig();
      expect(config).toEqual(getDefaultConfig());
    } finally {
      process.chdir(originalCwd);
      fs.rmSync(emptyDir, { recursive: true, force: true });
    }
  });

  it('should return defaults for empty YAML file', () => {
    const configPath = writeTempConfig('');
    const config = loadConfig(configPath);

    expect(config).toEqual(getDefaultConfig());
  });

  it('should return defaults for YAML with only null', () => {
    const configPath = writeTempConfig('null');
    const config = loadConfig(configPath);

    expect(config).toEqual(getDefaultConfig());
  });

  it('should throw ConfigLoadError for non-existent explicit path', () => {
    expect(() => loadConfig('/non/existent/path/clawsec.yaml')).toThrow(ConfigLoadError);
  });

  it('should throw ConfigValidationError for invalid YAML content', () => {
    const configContent = `
global:
  logLevel: invalid_level
`;
    const configPath = writeTempConfig(configContent);

    expect(() => loadConfig(configPath)).toThrow(ConfigValidationError);
  });

  it('should handle complex nested configuration', () => {
    const configContent = `
version: "1.0"
global:
  enabled: true
  logLevel: info
llm:
  enabled: true
  model: gpt-4-turbo
rules:
  purchase:
    enabled: true
    severity: critical
    action: block
    spendLimits:
      perTransaction: 25
      daily: 100
    domains:
      mode: blocklist
      blocklist:
        - amazon.com
        - ebay.com
  website:
    enabled: true
    mode: allowlist
    severity: high
    action: warn
    blocklist:
      - "*.malware.com"
      - "phishing-*.com"
    allowlist:
      - github.com
      - stackoverflow.com
  destructive:
    enabled: true
    severity: critical
    action: confirm
    shell:
      enabled: true
    cloud:
      enabled: false
    code:
      enabled: true
approval:
  native:
    enabled: true
    timeout: 600
  agentConfirm:
    enabled: false
    parameterName: _custom_confirm
  webhook:
    enabled: true
    url: https://api.company.com/clawsec/approve
    timeout: 30
    headers:
      X-API-Key: secret123
`;
    const configPath = writeTempConfig(configContent);
    const config = loadConfig(configPath);

    expect(config.llm.model).toBe('gpt-4-turbo');
    expect(config.rules.purchase.spendLimits.perTransaction).toBe(25);
    expect(config.rules.purchase.domains.blocklist).toContain('ebay.com');
    expect(config.rules.website.mode).toBe('allowlist');
    expect(config.rules.destructive.cloud.enabled).toBe(false);
    expect(config.approval.native.timeout).toBe(600);
    expect(config.approval.agentConfirm.enabled).toBe(false);
    expect(config.approval.webhook.enabled).toBe(true);
    expect(config.approval.webhook.headers['X-API-Key']).toBe('secret123');
  });
});

describe('loadConfigFromString', () => {
  it('should parse YAML string', () => {
    const yaml = `
version: "1.0"
global:
  logLevel: debug
`;
    const config = loadConfigFromString(yaml);
    expect(config.version).toBe('1.0');
    expect(config.global.logLevel).toBe('debug');
  });

  it('should return defaults for empty string', () => {
    const config = loadConfigFromString('');
    expect(config).toEqual(getDefaultConfig());
  });
});

describe('findConfigFile', () => {
  beforeEach(() => {
    tempDir = createTempDir();
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('should find clawsec.yaml in directory', () => {
    writeTempConfig('version: "1.0"', 'clawsec.yaml');
    const found = findConfigFile(tempDir);
    expect(found).toBe(path.join(tempDir, 'clawsec.yaml'));
  });

  it('should find clawsec.yml in directory', () => {
    writeTempConfig('version: "1.0"', 'clawsec.yml');
    const found = findConfigFile(tempDir);
    expect(found).toBe(path.join(tempDir, 'clawsec.yml'));
  });

  it('should find .clawsec.yaml (hidden file)', () => {
    writeTempConfig('version: "1.0"', '.clawsec.yaml');
    const found = findConfigFile(tempDir);
    expect(found).toBe(path.join(tempDir, '.clawsec.yaml'));
  });

  it('should prefer clawsec.yaml over clawsec.yml', () => {
    writeTempConfig('version: "1.0"', 'clawsec.yaml');
    writeTempConfig('version: "2.0"', 'clawsec.yml');
    const found = findConfigFile(tempDir);
    expect(found).toBe(path.join(tempDir, 'clawsec.yaml'));
  });

  it('should return null when no config file found', () => {
    const found = findConfigFile(tempDir);
    expect(found).toBeNull();
  });

  it('should search parent directories', () => {
    const subDir = path.join(tempDir, 'sub', 'deep', 'nested');
    fs.mkdirSync(subDir, { recursive: true });
    writeTempConfig('version: "1.0"', 'clawsec.yaml');

    const found = findConfigFile(subDir);
    expect(found).toBe(path.join(tempDir, 'clawsec.yaml'));
  });
});

// =============================================================================
// ERROR HANDLING TESTS
// =============================================================================

describe('ConfigValidationError', () => {
  it('should contain path and message for each error', () => {
    try {
      validateConfig({
        global: { logLevel: 'invalid' },
      });
      expect.fail('Should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigValidationError);
      const validationError = error as ConfigValidationError;
      expect(validationError.name).toBe('ConfigValidationError');
      expect(validationError.errors).toBeInstanceOf(Array);
      expect(validationError.errors[0]).toHaveProperty('path');
      expect(validationError.errors[0]).toHaveProperty('message');
    }
  });
});

describe('ConfigLoadError', () => {
  it('should contain file path', () => {
    const fakeP = '/fake/path/config.yaml';
    try {
      loadConfig(fakeP);
      expect.fail('Should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigLoadError);
      const loadError = error as ConfigLoadError;
      expect(loadError.name).toBe('ConfigLoadError');
      expect(loadError.filePath).toBe(fakeP);
    }
  });
});

// =============================================================================
// EDGE CASES
// =============================================================================

describe('Edge Cases', () => {
  beforeEach(() => {
    tempDir = createTempDir();
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('should handle YAML with comments', () => {
    const configContent = `
# This is a comment
version: "1.0"  # inline comment
global:
  # Another comment
  enabled: true
`;
    const configPath = writeTempConfig(configContent);
    const config = loadConfig(configPath);
    expect(config.version).toBe('1.0');
  });

  it('should handle YAML with anchors and aliases', () => {
    const configContent = `
version: "1.0"
rules:
  purchase: &purchase_default
    enabled: true
    severity: critical
  # Could use alias if needed
`;
    const configPath = writeTempConfig(configContent);
    const config = loadConfig(configPath);
    expect(config.rules.purchase.enabled).toBe(true);
  });

  it('should handle glob patterns in domain lists', () => {
    const configContent = `
rules:
  website:
    blocklist:
      - "*.malware.com"
      - "phishing-*.com"
      - "*.*.darkweb.net"
`;
    const configPath = writeTempConfig(configContent);
    const config = loadConfig(configPath);
    expect(config.rules.website.blocklist).toContain('*.malware.com');
    expect(config.rules.website.blocklist).toContain('phishing-*.com');
    expect(config.rules.website.blocklist).toContain('*.*.darkweb.net');
  });

  it('should handle special characters in webhook headers', () => {
    const configContent = `
approval:
  webhook:
    enabled: true
    url: https://api.example.com/approve
    headers:
      Authorization: "Bearer abc123!@#$%"
      X-Custom-Header: "value with spaces"
`;
    const configPath = writeTempConfig(configContent);
    const config = loadConfig(configPath);
    expect(config.approval.webhook.headers['Authorization']).toBe('Bearer abc123!@#$%');
    expect(config.approval.webhook.headers['X-Custom-Header']).toBe('value with spaces');
  });

  it('should handle zero values correctly', () => {
    const configContent = `
rules:
  purchase:
    spendLimits:
      perTransaction: 0
      daily: 0
approval:
  native:
    timeout: 1
`;
    const configPath = writeTempConfig(configContent);
    const config = loadConfig(configPath);
    expect(config.rules.purchase.spendLimits.perTransaction).toBe(0);
    expect(config.rules.purchase.spendLimits.daily).toBe(0);
  });

  it('should handle empty arrays', () => {
    const configContent = `
rules:
  purchase:
    domains:
      blocklist: []
  website:
    blocklist: []
    allowlist: []
`;
    const configPath = writeTempConfig(configContent);
    const config = loadConfig(configPath);
    expect(config.rules.purchase.domains.blocklist).toEqual([]);
    expect(config.rules.website.blocklist).toEqual([]);
    expect(config.rules.website.allowlist).toEqual([]);
  });
});

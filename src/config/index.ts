/**
 * Clawsec Configuration Module
 * Re-exports for clean imports
 */

// Schema and types
export {
  // Enums
  SeveritySchema,
  ActionSchema,
  LogLevelSchema,
  FilterModeSchema,
  // Enum types
  type Severity,
  type Action,
  type LogLevel,
  type FilterMode,
  // Global config
  GlobalConfigSchema,
  type GlobalConfig,
  // LLM config
  LLMConfigSchema,
  type LLMConfig,
  // Purchase rule
  SpendLimitsSchema,
  PurchaseDomainsSchema,
  PurchaseRuleSchema,
  type SpendLimits,
  type PurchaseDomains,
  type PurchaseRule,
  // Website rule
  WebsiteRuleSchema,
  type WebsiteRule,
  // Destructive rule
  ShellProtectionSchema,
  CloudProtectionSchema,
  CodeProtectionSchema,
  DestructiveRuleSchema,
  type ShellProtection,
  type CloudProtection,
  type CodeProtection,
  type DestructiveRule,
  // Secrets rule
  SecretsRuleSchema,
  type SecretsRule,
  // Exfiltration rule
  ExfiltrationRuleSchema,
  type ExfiltrationRule,
  // Rules config
  RulesConfigSchema,
  type RulesConfig,
  // Approval config
  NativeApprovalSchema,
  AgentConfirmSchema,
  WebhookApprovalSchema,
  ApprovalConfigSchema,
  type NativeApproval,
  type AgentConfirm,
  type WebhookApproval,
  type ApprovalConfig,
  // Root config
  ClawsecConfigSchema,
  type ClawsecConfig,
  type PartialClawsecConfig,
} from './schema.js';

// Defaults
export { defaultConfig, getDefaultConfig } from './defaults.js';

// Loader
export {
  // Error types
  ConfigValidationError,
  ConfigLoadError,
  // Validation functions
  validateConfig,
  isValidConfig,
  // Merging functions
  mergeWithDefaults,
  mergeConfigs,
  // File loading functions
  findConfigFile,
  loadConfig,
  loadConfigFromString,
} from './loader.js';

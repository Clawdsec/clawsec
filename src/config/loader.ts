/**
 * Clawsec Configuration Loader
 * YAML file loading and validation utilities
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { ClawsecConfigSchema, type ClawsecConfig, type PartialClawsecConfig } from './schema.js';
import { getDefaultConfig } from './defaults.js';

// =============================================================================
// ERROR TYPES
// =============================================================================

/**
 * Error thrown when configuration validation fails
 */
export class ConfigValidationError extends Error {
  constructor(
    message: string,
    public readonly errors: Array<{ path: string; message: string }>
  ) {
    super(message);
    this.name = 'ConfigValidationError';
  }

  /**
   * Create a ConfigValidationError from a ZodError
   */
  static fromZodError(zodError: z.ZodError): ConfigValidationError {
    const errors = zodError.issues.map((issue) => ({
      path: issue.path.map(String).join('.'),
      message: issue.message,
    }));
    const message = `Configuration validation failed:\n${errors
      .map((e) => `  - ${e.path || '(root)'}: ${e.message}`)
      .join('\n')}`;
    return new ConfigValidationError(message, errors);
  }
}

/**
 * Error thrown when configuration file cannot be loaded
 */
export class ConfigLoadError extends Error {
  constructor(
    message: string,
    public readonly filePath: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'ConfigLoadError';
  }
}

// =============================================================================
// VALIDATION
// =============================================================================

/**
 * Validates a configuration object using the Zod schema.
 *
 * @param config - Unknown configuration object to validate
 * @returns Validated and typed configuration
 * @throws ConfigValidationError if validation fails
 */
export function validateConfig(config: unknown): ClawsecConfig {
  const result = ClawsecConfigSchema.safeParse(config);

  if (!result.success) {
    throw ConfigValidationError.fromZodError(result.error);
  }

  return result.data;
}

/**
 * Checks if a configuration object is valid without throwing.
 *
 * @param config - Unknown configuration object to validate
 * @returns Object with success status and either data or errors
 */
export function isValidConfig(
  config: unknown
): { valid: true; config: ClawsecConfig } | { valid: false; errors: Array<{ path: string; message: string }> } {
  const result = ClawsecConfigSchema.safeParse(config);

  if (result.success) {
    return { valid: true, config: result.data };
  }

  return {
    valid: false,
    errors: result.error.issues.map((issue) => ({
      path: issue.path.map(String).join('.'),
      message: issue.message,
    })),
  };
}

// =============================================================================
// MERGING
// =============================================================================

/**
 * Deep merges a partial configuration with the default configuration.
 * Partial config values take precedence over defaults.
 *
 * @param partial - Partial configuration object
 * @returns Complete configuration merged with defaults
 */
export function mergeWithDefaults(partial: PartialClawsecConfig): ClawsecConfig {
  // Zod's parse with defaults handles the merging for us
  // by applying defaults for any missing fields
  return validateConfig(partial);
}

// =============================================================================
// FILE LOADING
// =============================================================================

/**
 * Standard config file names to look for
 */
const CONFIG_FILE_NAMES = ['clawsec.yaml', 'clawsec.yml', '.clawsec.yaml', '.clawsec.yml'];

/**
 * Reads and parses a YAML configuration file.
 *
 * @param filePath - Path to the YAML file
 * @returns Parsed YAML content as unknown
 * @throws ConfigLoadError if file cannot be read or parsed
 */
function readYamlFile(filePath: string): unknown {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    return parseYaml(content);
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
      throw new ConfigLoadError(`Configuration file not found: ${filePath}`, filePath, error as Error);
    }
    if (error instanceof Error) {
      throw new ConfigLoadError(`Failed to parse YAML file: ${error.message}`, filePath, error);
    }
    throw new ConfigLoadError(`Failed to read configuration file`, filePath);
  }
}

/**
 * Finds a configuration file in the specified directory or its parents.
 *
 * @param startDir - Directory to start searching from
 * @returns Path to found config file, or null if not found
 */
export function findConfigFile(startDir: string = process.cwd()): string | null {
  let currentDir = path.resolve(startDir);
  const root = path.parse(currentDir).root;

  while (currentDir !== root) {
    for (const fileName of CONFIG_FILE_NAMES) {
      const filePath = path.join(currentDir, fileName);
      if (fs.existsSync(filePath)) {
        return filePath;
      }
    }
    currentDir = path.dirname(currentDir);
  }

  // Check root directory as well
  for (const fileName of CONFIG_FILE_NAMES) {
    const filePath = path.join(root, fileName);
    if (fs.existsSync(filePath)) {
      return filePath;
    }
  }

  return null;
}

/**
 * Loads configuration from a YAML file.
 *
 * If no path is provided, searches for config file in standard locations.
 * If no config file is found, returns default configuration.
 *
 * @param configPath - Optional path to configuration file
 * @returns Validated configuration
 * @throws ConfigLoadError if specified file doesn't exist or can't be parsed
 * @throws ConfigValidationError if configuration is invalid
 */
export function loadConfig(configPath?: string): ClawsecConfig {
  // If explicit path provided, load from that path
  if (configPath) {
    const resolvedPath = path.resolve(configPath);
    const content = readYamlFile(resolvedPath);

    // Handle empty file case
    if (content === null || content === undefined) {
      return getDefaultConfig();
    }

    return validateConfig(content);
  }

  // Try to find config file
  const foundPath = findConfigFile();

  if (foundPath) {
    const content = readYamlFile(foundPath);

    // Handle empty file case
    if (content === null || content === undefined) {
      return getDefaultConfig();
    }

    return validateConfig(content);
  }

  // No config file found, return defaults
  return getDefaultConfig();
}

/**
 * Loads configuration from a YAML string.
 *
 * @param yamlContent - YAML string to parse
 * @returns Validated configuration
 * @throws ConfigValidationError if configuration is invalid
 */
export function loadConfigFromString(yamlContent: string): ClawsecConfig {
  const content = parseYaml(yamlContent);

  // Handle empty content
  if (content === null || content === undefined) {
    return getDefaultConfig();
  }

  return validateConfig(content);
}

/**
 * Loads and merges configuration from multiple sources.
 * Later sources override earlier ones.
 *
 * @param sources - Array of config objects to merge
 * @returns Merged and validated configuration
 */
export function mergeConfigs(...sources: PartialClawsecConfig[]): ClawsecConfig {
  // Start with an empty object and deep merge all sources
  const merged = sources.reduce<Record<string, unknown>>(
    (acc, source) => deepMerge(acc, source as Record<string, unknown>),
    {}
  );

  return validateConfig(merged);
}

/**
 * Deep merges two objects. Source values override target values.
 */
function deepMerge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  const result = { ...target };

  for (const key of Object.keys(source)) {
    const sourceValue = source[key];
    const targetValue = result[key];

    if (isPlainObject(sourceValue) && isPlainObject(targetValue)) {
      result[key] = deepMerge(
        targetValue as Record<string, unknown>,
        sourceValue as Record<string, unknown>
      );
    } else if (sourceValue !== undefined) {
      result[key] = sourceValue;
    }
  }

  return result;
}

/**
 * Checks if a value is a plain object (not an array, null, or other type)
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

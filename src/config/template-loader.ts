/**
 * Template Loading and Merging System
 *
 * Handles resolution of builtin templates, loading YAML files,
 * and deep merging of configuration objects with special array handling.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import type { PartialClawsecConfig } from './schema.js';
import { ConfigLoadError } from './loader.js';

/**
 * Resolves builtin template names to file paths
 */
export class TemplateResolver {
  private builtinPath: string;

  constructor() {
    // Resolve to rules/builtin/ relative to this file
    // From dist/src/config/template-loader.js → ../../../rules/builtin
    const currentDir = path.dirname(fileURLToPath(import.meta.url));
    // Go up from dist/src/config/ to project root, then into rules/builtin/
    this.builtinPath = path.join(currentDir, '../../../rules/builtin');
  }

  /**
   * Resolve template name to file path
   * "builtin/aws-security" → "/path/to/rules/builtin/aws-security.yaml"
   */
  resolveTemplatePath(templateName: string): string {
    if (templateName.startsWith('builtin/')) {
      const name = templateName.replace('builtin/', '');
      const filePath = path.join(this.builtinPath, `${name}.yaml`);

      // Check if file exists
      if (!fs.existsSync(filePath)) {
        throw new ConfigLoadError(
          `Built-in template not found: ${templateName}`,
          filePath
        );
      }

      return filePath;
    }

    // Assume it's a file path
    return path.resolve(templateName);
  }

  /**
   * Load a single template file
   */
  loadTemplate(templateName: string): PartialClawsecConfig {
    const filePath = this.resolveTemplatePath(templateName);

    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const parsed = parseYaml(content) as PartialClawsecConfig;

      // Remove template metadata fields (name, description, version)
      // These are for documentation only
      if (parsed && typeof parsed === 'object') {
        delete (parsed as Record<string, unknown>).name;
        delete (parsed as Record<string, unknown>).description;
      }

      return parsed || {};
    } catch (error) {
      throw new ConfigLoadError(
        `Failed to load template ${templateName}: ${error instanceof Error ? error.message : String(error)}`,
        filePath,
        error instanceof Error ? error : undefined
      );
    }
  }
}

/**
 * Deep merge arrays by concatenating them and removing duplicates
 * For patterns arrays: [...templatePatterns, ...userPatterns]
 */
function mergeArrays<T>(target: T[], source: T[]): T[] {
  // Remove duplicates while preserving order
  const combined = [...target, ...source];
  return Array.from(new Set(combined));
}

/**
 * Deep merge two configs, with special handling for arrays
 */
export function deepMergeConfigs(
  target: PartialClawsecConfig = {},
  source: PartialClawsecConfig = {}
): PartialClawsecConfig {
  const result: Record<string, unknown> = { ...target };

  for (const [key, sourceValue] of Object.entries(source || {})) {
    const targetValue = result[key];

    // Array merging: concatenate and dedupe
    if (Array.isArray(sourceValue) && Array.isArray(targetValue)) {
      result[key] = mergeArrays(targetValue, sourceValue);
    }
    // Object merging: recurse
    else if (
      isPlainObject(sourceValue) &&
      isPlainObject(targetValue)
    ) {
      result[key] = deepMergeConfigs(
        targetValue as PartialClawsecConfig,
        sourceValue as PartialClawsecConfig
      );
    }
    // Value override: source wins
    else if (sourceValue !== undefined) {
      result[key] = sourceValue;
    }
  }

  return result as PartialClawsecConfig;
}

/**
 * Check if value is a plain object (not array, not null)
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Load and merge multiple templates in order
 */
export function loadTemplates(templateNames: string[]): PartialClawsecConfig {
  const resolver = new TemplateResolver();
  let merged: PartialClawsecConfig = {};

  for (const templateName of templateNames) {
    const template = resolver.loadTemplate(templateName);
    merged = deepMergeConfigs(merged, template);
  }

  return merged;
}

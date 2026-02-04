/**
 * Purchase Detector
 * Main detector that combines domain, URL, and form field detection
 */

import type {
  DetectionContext,
  DetectionResult,
  PurchaseDetector as IPurchaseDetector,
  PurchaseDetectorConfig,
} from './types.js';
import { DomainDetector, createDomainDetector } from './domain-detector.js';
import { UrlDetector, createUrlDetector } from './url-detector.js';
import { FormDetector, createFormDetector } from './form-detector.js';
import type { PurchaseRule, Severity } from '../../config/index.js';

// Re-export types
export * from './types.js';

// Re-export sub-detectors
export { DomainDetector, createDomainDetector } from './domain-detector.js';
export { UrlDetector, createUrlDetector } from './url-detector.js';
export { FormDetector, createFormDetector } from './form-detector.js';
export {
  extractDomain,
  matchDomain,
  globToRegex,
  matchesGlobPattern,
  hasPaymentKeyword,
} from './domain-detector.js';
export { extractPath, matchUrlPath } from './url-detector.js';
export { matchFormFields, containsPaymentValues } from './form-detector.js';

/**
 * No detection result (used when disabled or no match)
 */
function noDetection(severity: Severity): DetectionResult {
  return {
    detected: false,
    category: 'purchase',
    severity,
    confidence: 0,
    reason: 'No purchase activity detected',
  };
}

/**
 * Combine multiple detection results, taking the highest confidence
 */
function combineResults(results: (DetectionResult | null)[], severity: Severity): DetectionResult {
  const validResults = results.filter((r): r is DetectionResult => r !== null && r.detected);
  
  if (validResults.length === 0) {
    return noDetection(severity);
  }
  
  // Sort by confidence (highest first)
  validResults.sort((a, b) => b.confidence - a.confidence);
  
  // Take the highest confidence result as primary
  const primary = validResults[0];
  
  // Merge metadata from all results
  const mergedMetadata: DetectionResult['metadata'] = {
    ...primary.metadata,
  };
  
  // Collect all form fields
  const allFormFields: string[] = [];
  for (const result of validResults) {
    if (result.metadata?.formFields) {
      allFormFields.push(...result.metadata.formFields);
    }
  }
  if (allFormFields.length > 0) {
    mergedMetadata.formFields = [...new Set(allFormFields)];
  }
  
  // Build combined reason
  let reason = primary.reason;
  if (validResults.length > 1) {
    const additionalReasons = validResults.slice(1).map(r => r.reason);
    reason = `${primary.reason}. Additional signals: ${additionalReasons.join('; ')}`;
  }
  
  // Boost confidence if multiple detectors triggered
  let confidence = primary.confidence;
  if (validResults.length >= 2) {
    // Boost confidence but cap at 0.99
    confidence = Math.min(0.99, confidence + 0.05 * (validResults.length - 1));
  }
  
  return {
    detected: true,
    category: 'purchase',
    severity,
    confidence,
    reason,
    metadata: mergedMetadata,
  };
}

/**
 * Main purchase detector implementation
 */
export class PurchaseDetectorImpl implements IPurchaseDetector {
  private config: PurchaseDetectorConfig;
  private domainDetector: DomainDetector;
  private urlDetector: UrlDetector;
  private formDetector: FormDetector;

  constructor(config: PurchaseDetectorConfig) {
    this.config = config;
    
    const customBlocklist = config.domains?.mode === 'blocklist' 
      ? (config.domains.blocklist || [])
      : [];
    
    this.domainDetector = createDomainDetector(config.severity, customBlocklist);
    this.urlDetector = createUrlDetector(config.severity);
    this.formDetector = createFormDetector(config.severity);
  }

  async detect(context: DetectionContext): Promise<DetectionResult> {
    // Check if detector is enabled
    if (!this.config.enabled) {
      return noDetection(this.config.severity);
    }

    // Run all sub-detectors
    const domainResult = this.domainDetector.detect(context);
    const urlResult = this.urlDetector.detect(context);
    const formResult = this.formDetector.detect(context);

    // Combine results
    return combineResults([domainResult, urlResult, formResult], this.config.severity);
  }

  /**
   * Get the configured action for detected purchases
   */
  getAction() {
    return this.config.action;
  }

  /**
   * Check if the detector is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }
}

/**
 * Create a purchase detector from PurchaseRule configuration
 */
export function createPurchaseDetector(rule: PurchaseRule): PurchaseDetectorImpl {
  const config: PurchaseDetectorConfig = {
    enabled: rule.enabled,
    severity: rule.severity,
    action: rule.action,
    domains: rule.domains ? {
      mode: rule.domains.mode,
      blocklist: rule.domains.blocklist,
    } : undefined,
  };
  
  return new PurchaseDetectorImpl(config);
}

/**
 * Create a purchase detector with default configuration
 */
export function createDefaultPurchaseDetector(): PurchaseDetectorImpl {
  return new PurchaseDetectorImpl({
    enabled: true,
    severity: 'critical',
    action: 'block',
  });
}

// Default export
export default PurchaseDetectorImpl;

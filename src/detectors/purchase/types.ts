/**
 * Purchase Detector Types
 * Type definitions for the purchase/transaction detection system
 */

import type { Severity, Action } from '../../config/index.js';

/**
 * Detection context passed to detectors
 */
export interface DetectionContext {
  /** Name of the tool being invoked */
  toolName: string;
  /** Input parameters to the tool */
  toolInput: Record<string, unknown>;
  /** URL being accessed (for browser/navigation tools) */
  url?: string;
}

/**
 * Result of a detection operation
 */
export interface DetectionResult {
  /** Whether a purchase/transaction was detected */
  detected: boolean;
  /** Category of the detection */
  category: 'purchase';
  /** Severity level of the detection */
  severity: Severity;
  /** Confidence score from 0 to 1 */
  confidence: number;
  /** Human-readable reason for the detection */
  reason: string;
  /** Additional metadata about the detection */
  metadata?: {
    /** Domain that triggered the detection */
    domain?: string;
    /** URL that triggered the detection */
    url?: string;
    /** Form fields that triggered the detection */
    formFields?: string[];
    /** Pattern that matched */
    matchedPattern?: string;
  };
}

/**
 * Configuration for the purchase detector
 */
export interface PurchaseDetectorConfig {
  /** Whether the detector is enabled */
  enabled: boolean;
  /** Severity level to assign to detections */
  severity: Severity;
  /** Action to take when purchase is detected */
  action: Action;
  /** Domain configuration */
  domains?: {
    /** Mode for domain filtering */
    mode: 'blocklist' | 'allowlist';
    /** Domains to block */
    blocklist: string[];
  };
}

/**
 * Interface for the main purchase detector
 */
export interface PurchaseDetector {
  /**
   * Detect purchase/transaction attempts
   * @param context Detection context with tool information
   * @returns Detection result
   */
  detect(context: DetectionContext): Promise<DetectionResult>;
}

/**
 * Interface for sub-detectors (domain, URL, form)
 */
export interface SubDetector {
  /**
   * Check if the given context matches this detector's patterns
   * @param context Detection context
   * @returns Detection result or null if no match
   */
  detect(context: DetectionContext): DetectionResult | null;
}

/**
 * Domain match result with confidence
 */
export interface DomainMatchResult {
  /** Whether a match was found */
  matched: boolean;
  /** The domain that matched */
  domain?: string;
  /** The pattern that matched */
  pattern?: string;
  /** Match type */
  matchType?: 'exact' | 'glob' | 'keyword';
  /** Confidence score */
  confidence: number;
}

/**
 * URL match result with confidence
 */
export interface UrlMatchResult {
  /** Whether a match was found */
  matched: boolean;
  /** The URL that matched */
  url?: string;
  /** The pattern that matched */
  pattern?: string;
  /** Match type */
  matchType?: 'path' | 'api';
  /** Confidence score */
  confidence: number;
}

/**
 * Form field match result
 */
export interface FormFieldMatchResult {
  /** Whether a match was found */
  matched: boolean;
  /** Fields that matched */
  fields?: string[];
  /** Patterns that matched */
  patterns?: string[];
  /** Confidence score */
  confidence: number;
}

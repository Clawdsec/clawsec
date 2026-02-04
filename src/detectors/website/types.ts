/**
 * Website Detector Types
 * Type definitions for the website access control system
 */

import type { Severity, Action, FilterMode } from '../../config/index.js';

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
 * Website categories for additional detection
 */
export type WebsiteCategory = 'malware' | 'phishing' | 'gambling' | 'adult' | 'unknown';

/**
 * Result of a website detection operation
 */
export interface WebsiteDetectionResult {
  /** Whether the website should be blocked/warned */
  detected: boolean;
  /** Category of the detection */
  category: 'website';
  /** Severity level of the detection */
  severity: Severity;
  /** Confidence score from 0 to 1 */
  confidence: number;
  /** Human-readable reason for the detection */
  reason: string;
  /** Additional metadata about the detection */
  metadata?: {
    /** URL that triggered the detection */
    url?: string;
    /** Domain that triggered the detection */
    domain?: string;
    /** Pattern that matched */
    matchedPattern?: string;
    /** Filter mode that was used */
    mode: FilterMode;
    /** Detected website category (malware, phishing, etc.) */
    websiteCategory?: WebsiteCategory;
  };
}

/**
 * Configuration for the website detector
 */
export interface WebsiteDetectorConfig {
  /** Whether the detector is enabled */
  enabled: boolean;
  /** Mode for website filtering */
  mode: FilterMode;
  /** Severity level to assign to detections */
  severity: Severity;
  /** Action to take when website is blocked */
  action: Action;
  /** Websites to block (supports glob patterns) */
  blocklist: string[];
  /** Websites to allow (supports glob patterns) */
  allowlist: string[];
}

/**
 * Interface for the main website detector
 */
export interface WebsiteDetector {
  /**
   * Detect website access violations
   * @param context Detection context with tool information
   * @returns Detection result
   */
  detect(context: DetectionContext): Promise<WebsiteDetectionResult>;
}

/**
 * Pattern match result with confidence
 */
export interface PatternMatchResult {
  /** Whether a match was found */
  matched: boolean;
  /** The domain that matched */
  domain?: string;
  /** The pattern that matched */
  pattern?: string;
  /** Match type */
  matchType?: 'exact' | 'glob';
  /** Confidence score */
  confidence: number;
}

/**
 * Category detection result
 */
export interface CategoryDetectionResult {
  /** Whether a category was detected */
  detected: boolean;
  /** The detected category */
  category?: WebsiteCategory;
  /** The pattern that matched */
  matchedPattern?: string;
  /** Confidence score */
  confidence: number;
}

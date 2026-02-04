/**
 * Exfiltration Detector
 * Main export for detecting data exfiltration attempts via HTTP, cloud, and network methods
 */

// Re-export types
export type {
  DetectionContext,
  ExfiltrationMethod,
  ExfiltrationDetectionResult,
  ExfiltrationDetectorConfig,
  ExfiltrationDetector as IExfiltrationDetector,
  SubDetector,
  HttpMatchResult,
  CloudUploadMatchResult,
  NetworkMatchResult,
} from './types.js';

// Re-export HTTP detector
export {
  HttpDetector,
  createHttpDetector,
  matchCurlCommand,
  matchWgetCommand,
  matchHttpieCommand,
  matchCodeHttpPattern,
  matchEncodedExfiltration,
  matchHttpExfiltration,
} from './http-detector.js';

// Re-export cloud upload detector
export {
  CloudUploadDetector,
  createCloudUploadDetector,
  matchAwsS3Upload,
  matchGcpUpload,
  matchAzureUpload,
  matchRcloneUpload,
  matchOtherCloudUpload,
  matchCloudSdkUpload,
  matchCloudUpload,
} from './cloud-detector.js';

// Re-export network detector
export {
  NetworkDetector,
  createNetworkDetector,
  matchNetcatCommand,
  matchDevTcpPattern,
  matchSocatCommand,
  matchTelnetCommand,
  matchSshExfiltration,
  matchDnsExfiltration,
  matchOtherNetworkPattern,
  matchNetworkExfiltration,
} from './network-detector.js';

import type {
  DetectionContext,
  ExfiltrationDetectionResult,
  ExfiltrationDetectorConfig,
  ExfiltrationDetector,
} from './types.js';
import { HttpDetector, createHttpDetector } from './http-detector.js';
import { CloudUploadDetector, createCloudUploadDetector } from './cloud-detector.js';
import { NetworkDetector, createNetworkDetector } from './network-detector.js';
import type { Severity, ExfiltrationRule } from '../../config/index.js';

/**
 * Create a no-detection result
 */
function noDetection(severity: Severity): ExfiltrationDetectionResult {
  return {
    detected: false,
    category: 'exfiltration',
    severity,
    confidence: 0,
    reason: 'No exfiltration detected',
  };
}

/**
 * Combine results from multiple sub-detectors
 */
function combineResults(
  results: (ExfiltrationDetectionResult | null)[],
  defaultSeverity: Severity
): ExfiltrationDetectionResult {
  // Filter out null results
  const validResults = results.filter(
    (r): r is ExfiltrationDetectionResult => r !== null && r.detected
  );

  if (validResults.length === 0) {
    return noDetection(defaultSeverity);
  }

  // Sort by confidence (highest first)
  validResults.sort((a, b) => b.confidence - a.confidence);

  // Take the highest confidence result
  const best = validResults[0];

  // Boost confidence if multiple detectors matched
  let confidence = best.confidence;
  if (validResults.length > 1) {
    // Boost by 5% for each additional detection, max 0.99
    confidence = Math.min(0.99, confidence + (validResults.length - 1) * 0.05);
  }

  return {
    ...best,
    confidence,
    reason: validResults.length > 1
      ? `${best.reason} (confirmed by ${validResults.length} detection methods)`
      : best.reason,
  };
}

/**
 * Main exfiltration detector implementation
 */
export class ExfiltrationDetectorImpl implements ExfiltrationDetector {
  private config: ExfiltrationDetectorConfig;
  private httpDetector: HttpDetector;
  private cloudDetector: CloudUploadDetector;
  private networkDetector: NetworkDetector;

  constructor(config: ExfiltrationDetectorConfig) {
    this.config = config;

    // Initialize sub-detectors
    this.httpDetector = createHttpDetector(config.severity);
    this.cloudDetector = createCloudUploadDetector(config.severity);
    this.networkDetector = createNetworkDetector(config.severity);
  }

  async detect(context: DetectionContext): Promise<ExfiltrationDetectionResult> {
    // Check if detector is enabled
    if (!this.config.enabled) {
      return noDetection(this.config.severity);
    }

    const results: (ExfiltrationDetectionResult | null)[] = [];

    // Run HTTP detector
    results.push(this.httpDetector.detect(context));

    // Run cloud upload detector
    results.push(this.cloudDetector.detect(context));

    // Run network detector
    results.push(this.networkDetector.detect(context));

    // Combine results
    return combineResults(results, this.config.severity);
  }

  /**
   * Get the configured action for detected exfiltration
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
 * Create an exfiltration detector from configuration
 */
export function createExfiltrationDetector(
  config: ExfiltrationDetectorConfig | ExfiltrationRule
): ExfiltrationDetectorImpl {
  return new ExfiltrationDetectorImpl(config);
}

/**
 * Create a default exfiltration detector with standard settings
 */
export function createDefaultExfiltrationDetector(): ExfiltrationDetectorImpl {
  return new ExfiltrationDetectorImpl({
    enabled: true,
    severity: 'high',
    action: 'block',
  });
}

// Default export
export default {
  ExfiltrationDetectorImpl,
  createExfiltrationDetector,
  createDefaultExfiltrationDetector,
};

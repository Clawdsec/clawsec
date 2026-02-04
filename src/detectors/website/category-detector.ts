/**
 * Category Detector
 * Detects website categories like malware, phishing, gambling, adult content
 */

import type { CategoryDetectionResult, WebsiteCategory } from './types.js';
import { matchesGlobPattern } from './pattern-matcher.js';

/**
 * Known malware domain patterns
 * These patterns match domains commonly associated with malware distribution
 */
const MALWARE_PATTERNS = [
  // Common malware domain patterns
  '*.malware.*',
  '*.virus.*',
  '*.trojan.*',
  '*.exploit.*',
  'malware-*.*',
  '*-malware.*',
  '*.malicious.*',
  
  // Suspicious TLDs often used for malware
  '*.xyz',
  '*.tk',
  '*.ml',
  '*.ga',
  '*.cf',
  '*.gq',
  
  // Download/crack sites (common malware vectors)
  '*crack*.*',
  '*keygen*.*',
  '*warez*.*',
  '*pirat*.*',
];

/**
 * Known phishing domain patterns
 * These patterns match domains commonly used for phishing attacks
 */
const PHISHING_PATTERNS = [
  // Phishing keyword patterns
  'phishing-*.*',
  '*-phishing.*',
  '*.phishing.*',
  
  // Common phishing techniques
  '*login-secure*.*',
  '*secure-login*.*',
  '*account-verify*.*',
  '*verify-account*.*',
  '*update-payment*.*',
  '*payment-update*.*',
  '*confirm-identity*.*',
  '*identity-confirm*.*',
  
  // Lookalike domain patterns (suspicious)
  '*-signin.*',
  '*signin-*.*',
  '*-login.*',
  '*login-*.*',
  '*paypa1*.*',      // Paypal with 1 instead of l
  '*g00gle*.*',      // Google with 0 instead of o
  '*amaz0n*.*',      // Amazon with 0 instead of o
  '*faceb00k*.*',    // Facebook with 0 instead of o
  '*micros0ft*.*',   // Microsoft with 0 instead of o
  '*app1e*.*',       // Apple with 1 instead of l
  
  // Urgent action domains
  '*urgent-*.*',
  '*-urgent.*',
  '*suspended-*.*',
  '*-suspended.*',
];

/**
 * Gambling domain patterns
 */
const GAMBLING_PATTERNS = [
  '*.casino.*',
  '*.bet.*',
  '*.poker.*',
  '*.slots.*',
  '*.gambling.*',
  '*casino*.*',
  '*betting*.*',
  '*poker*.*',
  '*blackjack*.*',
  '*roulette*.*',
  '*lottery*.*',
  '*jackpot*.*',
  '*.888casino.*',
  '*.bet365.*',
  '*.pokerstars.*',
  '*.draftkings.*',
  '*.fanduel.*',
];

/**
 * Adult content domain patterns
 */
const ADULT_PATTERNS = [
  '*.adult.*',
  '*.xxx.*',
  '*.porn*.*',
  '*porn*.*',
  '*.sex.*',
  '*adult*.*',
  '*.nsfw.*',
  '*nsfw*.*',
];

/**
 * Category patterns with their severity
 */
const CATEGORY_PATTERNS: Array<{
  category: WebsiteCategory;
  patterns: string[];
  defaultConfidence: number;
}> = [
  { category: 'malware', patterns: MALWARE_PATTERNS, defaultConfidence: 0.85 },
  { category: 'phishing', patterns: PHISHING_PATTERNS, defaultConfidence: 0.80 },
  { category: 'gambling', patterns: GAMBLING_PATTERNS, defaultConfidence: 0.90 },
  { category: 'adult', patterns: ADULT_PATTERNS, defaultConfidence: 0.90 },
];

/**
 * Detect website category based on domain patterns
 */
export function detectCategory(domain: string): CategoryDetectionResult {
  const domainLower = domain.toLowerCase();
  
  for (const { category, patterns, defaultConfidence } of CATEGORY_PATTERNS) {
    for (const pattern of patterns) {
      if (matchesGlobPattern(domainLower, pattern)) {
        return {
          detected: true,
          category,
          matchedPattern: pattern,
          confidence: defaultConfidence,
        };
      }
    }
  }
  
  return {
    detected: false,
    confidence: 0,
  };
}

/**
 * Check if a category is considered dangerous (malware, phishing)
 */
export function isDangerousCategory(category: WebsiteCategory): boolean {
  return category === 'malware' || category === 'phishing';
}

/**
 * Check if a category is considered optional/warning-only (gambling, adult)
 */
export function isWarningCategory(category: WebsiteCategory): boolean {
  return category === 'gambling' || category === 'adult';
}

/**
 * Get severity description for a category
 */
export function getCategorySeverityDescription(category: WebsiteCategory): string {
  switch (category) {
    case 'malware':
      return 'potential malware distribution site';
    case 'phishing':
      return 'potential phishing site';
    case 'gambling':
      return 'gambling website';
    case 'adult':
      return 'adult content website';
    default:
      return 'unknown category';
  }
}

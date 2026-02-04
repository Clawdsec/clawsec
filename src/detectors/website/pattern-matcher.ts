/**
 * Pattern Matcher
 * Glob pattern matching for domains with support for * and ** wildcards
 */

import type { PatternMatchResult } from './types.js';

/**
 * Extract domain from URL
 */
export function extractDomain(url: string): string | null {
  try {
    // Handle URLs without protocol
    let normalizedUrl = url;
    if (!url.includes('://')) {
      normalizedUrl = 'https://' + url;
    }
    const parsed = new URL(normalizedUrl);
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Convert glob pattern to regex
 * Supports:
 * - * matches any sequence of characters except dots (single segment)
 * - ** matches any sequence of characters including dots (multiple segments)
 * - ? matches any single character
 */
export function globToRegex(pattern: string): RegExp {
  // Escape special regex characters except *, ?, and **
  let regex = pattern.toLowerCase();
  
  // First, handle ** (matches anything including dots)
  // Use a placeholder to preserve ** before processing single *
  regex = regex.replace(/\*\*/g, '<<<DOUBLE_STAR>>>');
  
  // Escape special regex characters
  regex = regex.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  
  // Convert single * to match anything except dots (single segment)
  regex = regex.replace(/\*/g, '[^.]*');
  
  // Convert ** placeholder back to match anything including dots
  regex = regex.replace(/<<<DOUBLE_STAR>>>/g, '.*');
  
  // Convert ? to match any single character
  regex = regex.replace(/\?/g, '.');
  
  return new RegExp(`^${regex}$`, 'i');
}

/**
 * Check if domain matches a glob pattern
 */
export function matchesGlobPattern(domain: string, pattern: string): boolean {
  const regex = globToRegex(pattern);
  return regex.test(domain.toLowerCase());
}

/**
 * Check if domain matches any pattern in a list
 */
export function matchesAnyPattern(domain: string, patterns: string[]): PatternMatchResult {
  const domainLower = domain.toLowerCase();
  
  for (const pattern of patterns) {
    const patternLower = pattern.toLowerCase();
    
    // Check for exact match first (highest confidence)
    if (domainLower === patternLower) {
      return {
        matched: true,
        domain: domainLower,
        pattern: pattern,
        matchType: 'exact',
        confidence: 0.99,
      };
    }
    
    // Check glob pattern match
    if (pattern.includes('*') || pattern.includes('?')) {
      if (matchesGlobPattern(domainLower, patternLower)) {
        return {
          matched: true,
          domain: domainLower,
          pattern: pattern,
          matchType: 'glob',
          confidence: 0.95,
        };
      }
    }
  }
  
  return {
    matched: false,
    confidence: 0,
  };
}

/**
 * Extract URL from detection context
 */
export function extractUrlFromContext(context: { 
  url?: string; 
  toolInput: Record<string, unknown> 
}): string | null {
  // Direct URL in context
  if (context.url) {
    return context.url;
  }
  
  // Check common tool input patterns
  const input = context.toolInput;
  
  // Browser navigation tools
  if (typeof input.url === 'string') {
    return input.url;
  }
  
  // Some tools use href
  if (typeof input.href === 'string') {
    return input.href;
  }
  
  // Check for URLs in link/target fields
  if (typeof input.link === 'string') {
    return input.link;
  }
  
  if (typeof input.target === 'string' && input.target.includes('://')) {
    return input.target;
  }
  
  // Check for URLs in src/source fields (for fetch/request tools)
  if (typeof input.src === 'string') {
    return input.src;
  }
  
  if (typeof input.source === 'string' && input.source.includes('://')) {
    return input.source;
  }
  
  return null;
}

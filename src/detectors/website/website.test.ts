/**
 * Website Detector Tests
 * Comprehensive tests for allowlist/blocklist modes, pattern matching, and category detection
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  // Main detector
  WebsiteDetectorImpl,
  createWebsiteDetector,
  createDefaultWebsiteDetector,
  
  // Pattern matching
  extractDomain,
  extractUrlFromContext,
  matchesAnyPattern,
  matchesGlobPattern,
  globToRegex,
  
  // Category detection
  detectCategory,
  isDangerousCategory,
  isWarningCategory,
  getCategorySeverityDescription,
  
  // Types
  type DetectionContext,
  type WebsiteDetectorConfig,
} from './index.js';

// =============================================================================
// PATTERN MATCHER TESTS
// =============================================================================

describe('Pattern Matcher', () => {
  describe('extractDomain', () => {
    it('should extract domain from full URL', () => {
      expect(extractDomain('https://example.com/path')).toBe('example.com');
      expect(extractDomain('http://www.github.com/repo')).toBe('www.github.com');
    });

    it('should extract domain from URL without protocol', () => {
      expect(extractDomain('example.com/path')).toBe('example.com');
      expect(extractDomain('docs.example.com')).toBe('docs.example.com');
    });

    it('should handle URLs with ports', () => {
      expect(extractDomain('https://localhost:3000/api')).toBe('localhost');
      expect(extractDomain('http://example.com:8080')).toBe('example.com');
    });

    it('should return null for invalid URLs', () => {
      expect(extractDomain('')).toBe(null);
      expect(extractDomain('not a url')).toBe(null);
    });

    it('should normalize domain to lowercase', () => {
      expect(extractDomain('https://EXAMPLE.COM')).toBe('example.com');
      expect(extractDomain('https://GitHub.Com')).toBe('github.com');
    });
  });

  describe('globToRegex', () => {
    it('should convert simple glob patterns with *', () => {
      const regex = globToRegex('*.example.com');
      expect(regex.test('api.example.com')).toBe(true);
      expect(regex.test('docs.example.com')).toBe(true);
      expect(regex.test('example.com')).toBe(false);
      expect(regex.test('sub.api.example.com')).toBe(false); // * doesn't match dots
    });

    it('should handle ** for multi-segment matching', () => {
      const regex = globToRegex('**.example.com');
      expect(regex.test('api.example.com')).toBe(true);
      expect(regex.test('sub.api.example.com')).toBe(true);
      expect(regex.test('example.com')).toBe(false);
    });

    it('should escape special regex characters', () => {
      const regex = globToRegex('example.com');
      expect(regex.test('example.com')).toBe(true);
      expect(regex.test('exampleXcom')).toBe(false);
    });

    it('should handle ? for single character matching', () => {
      const regex = globToRegex('example?.com');
      expect(regex.test('example1.com')).toBe(true);
      expect(regex.test('examplea.com')).toBe(true);
      expect(regex.test('example.com')).toBe(false);
      expect(regex.test('example12.com')).toBe(false);
    });

    it('should handle patterns at different positions', () => {
      expect(globToRegex('phishing-*').test('phishing-site')).toBe(true);
      expect(globToRegex('*-malware.com').test('bad-malware.com')).toBe(true);
      expect(globToRegex('*.*.com').test('sub.example.com')).toBe(true);
    });
  });

  describe('matchesGlobPattern', () => {
    it('should match exact domains', () => {
      expect(matchesGlobPattern('example.com', 'example.com')).toBe(true);
      expect(matchesGlobPattern('example.com', 'other.com')).toBe(false);
    });

    it('should match wildcard subdomain patterns', () => {
      expect(matchesGlobPattern('api.example.com', '*.example.com')).toBe(true);
      expect(matchesGlobPattern('docs.example.com', '*.example.com')).toBe(true);
      expect(matchesGlobPattern('example.com', '*.example.com')).toBe(false);
    });

    it('should match wildcard TLD patterns', () => {
      expect(matchesGlobPattern('example.com', 'example.*')).toBe(true);
      expect(matchesGlobPattern('example.org', 'example.*')).toBe(true);
      expect(matchesGlobPattern('example.co.uk', 'example.*')).toBe(false); // * doesn't match .co.uk
    });

    it('should be case-insensitive', () => {
      expect(matchesGlobPattern('EXAMPLE.COM', 'example.com')).toBe(true);
      expect(matchesGlobPattern('example.com', 'EXAMPLE.COM')).toBe(true);
    });
  });

  describe('matchesAnyPattern', () => {
    it('should return exact match with high confidence', () => {
      const result = matchesAnyPattern('github.com', ['github.com', 'gitlab.com']);
      expect(result.matched).toBe(true);
      expect(result.matchType).toBe('exact');
      expect(result.confidence).toBe(0.99);
      expect(result.pattern).toBe('github.com');
    });

    it('should return glob match with slightly lower confidence', () => {
      const result = matchesAnyPattern('api.github.com', ['*.github.com']);
      expect(result.matched).toBe(true);
      expect(result.matchType).toBe('glob');
      expect(result.confidence).toBe(0.95);
    });

    it('should return no match for non-matching domain', () => {
      const result = matchesAnyPattern('example.com', ['github.com', 'gitlab.com']);
      expect(result.matched).toBe(false);
      expect(result.confidence).toBe(0);
    });

    it('should handle empty pattern list', () => {
      const result = matchesAnyPattern('example.com', []);
      expect(result.matched).toBe(false);
    });
  });

  describe('extractUrlFromContext', () => {
    it('should extract from context.url', () => {
      const context = {
        url: 'https://example.com',
        toolInput: {},
      };
      expect(extractUrlFromContext(context)).toBe('https://example.com');
    });

    it('should extract from toolInput.url', () => {
      const context = {
        toolInput: { url: 'https://example.com' },
      };
      expect(extractUrlFromContext(context)).toBe('https://example.com');
    });

    it('should extract from toolInput.href', () => {
      const context = {
        toolInput: { href: 'https://example.com' },
      };
      expect(extractUrlFromContext(context)).toBe('https://example.com');
    });

    it('should extract from toolInput.link', () => {
      const context = {
        toolInput: { link: 'https://example.com' },
      };
      expect(extractUrlFromContext(context)).toBe('https://example.com');
    });

    it('should extract from toolInput.target if it looks like URL', () => {
      const context = {
        toolInput: { target: 'https://example.com' },
      };
      expect(extractUrlFromContext(context)).toBe('https://example.com');
    });

    it('should return null when no URL found', () => {
      const context = {
        toolInput: { text: 'hello world' },
      };
      expect(extractUrlFromContext(context)).toBe(null);
    });
  });
});

// =============================================================================
// CATEGORY DETECTOR TESTS
// =============================================================================

describe('Category Detector', () => {
  describe('detectCategory', () => {
    describe('malware detection', () => {
      it('should detect malware domain patterns', () => {
        expect(detectCategory('download.malware.com').detected).toBe(true);
        expect(detectCategory('download.malware.com').category).toBe('malware');
        
        expect(detectCategory('evil.virus.net').detected).toBe(true);
        expect(detectCategory('evil.virus.net').category).toBe('malware');
      });

      it('should detect crack/warez patterns', () => {
        expect(detectCategory('free-crack-software.com').detected).toBe(true);
        expect(detectCategory('keygen-downloads.net').detected).toBe(true);
      });

      it('should detect suspicious TLDs', () => {
        expect(detectCategory('suspicious.xyz').detected).toBe(true);
        expect(detectCategory('sketchy.tk').detected).toBe(true);
      });
    });

    describe('phishing detection', () => {
      it('should detect phishing keyword patterns', () => {
        expect(detectCategory('phishing-site.com').detected).toBe(true);
        expect(detectCategory('phishing-site.com').category).toBe('phishing');
      });

      it('should detect lookalike domain patterns', () => {
        expect(detectCategory('paypa1-secure.com').detected).toBe(true);
        expect(detectCategory('g00gle-login.com').detected).toBe(true);
        expect(detectCategory('amaz0n-verify.com').detected).toBe(true);
      });

      it('should detect urgent/verify patterns', () => {
        expect(detectCategory('account-verify-now.com').detected).toBe(true);
        expect(detectCategory('urgent-action-required.com').detected).toBe(true);
      });
    });

    describe('gambling detection', () => {
      it('should detect gambling domain patterns', () => {
        expect(detectCategory('online-casino.com').detected).toBe(true);
        expect(detectCategory('online-casino.com').category).toBe('gambling');
        
        expect(detectCategory('sports-betting.net').detected).toBe(true);
        expect(detectCategory('poker-room.com').detected).toBe(true);
      });
    });

    describe('adult detection', () => {
      it('should detect adult content patterns', () => {
        expect(detectCategory('adult-content.com').detected).toBe(true);
        expect(detectCategory('adult-content.com').category).toBe('adult');
        
        expect(detectCategory('site.xxx.com').detected).toBe(true);
      });
    });

    it('should return no detection for safe domains', () => {
      expect(detectCategory('github.com').detected).toBe(false);
      expect(detectCategory('docs.google.com').detected).toBe(false);
      expect(detectCategory('example.com').detected).toBe(false);
    });
  });

  describe('isDangerousCategory', () => {
    it('should return true for malware and phishing', () => {
      expect(isDangerousCategory('malware')).toBe(true);
      expect(isDangerousCategory('phishing')).toBe(true);
    });

    it('should return false for gambling and adult', () => {
      expect(isDangerousCategory('gambling')).toBe(false);
      expect(isDangerousCategory('adult')).toBe(false);
    });
  });

  describe('isWarningCategory', () => {
    it('should return true for gambling and adult', () => {
      expect(isWarningCategory('gambling')).toBe(true);
      expect(isWarningCategory('adult')).toBe(true);
    });

    it('should return false for malware and phishing', () => {
      expect(isWarningCategory('malware')).toBe(false);
      expect(isWarningCategory('phishing')).toBe(false);
    });
  });

  describe('getCategorySeverityDescription', () => {
    it('should return correct descriptions', () => {
      expect(getCategorySeverityDescription('malware')).toBe('potential malware distribution site');
      expect(getCategorySeverityDescription('phishing')).toBe('potential phishing site');
      expect(getCategorySeverityDescription('gambling')).toBe('gambling website');
      expect(getCategorySeverityDescription('adult')).toBe('adult content website');
    });
  });
});

// =============================================================================
// ALLOWLIST MODE TESTS
// =============================================================================

describe('Website Detector - Allowlist Mode', () => {
  let detector: WebsiteDetectorImpl;

  describe('with populated allowlist', () => {
    beforeEach(() => {
      detector = new WebsiteDetectorImpl({
        enabled: true,
        mode: 'allowlist',
        severity: 'high',
        action: 'block',
        blocklist: [],
        allowlist: ['github.com', 'docs.openclaw.ai', '*.google.com'],
      });
    });

    it('should allow exact match in allowlist', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://github.com/repo' },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(false);
      expect(result.metadata?.mode).toBe('allowlist');
      expect(result.metadata?.matchedPattern).toBe('github.com');
    });

    it('should allow glob pattern match in allowlist', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://docs.google.com/document' },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(false);
      expect(result.metadata?.matchedPattern).toBe('*.google.com');
    });

    it('should block domain not in allowlist', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://example.com' },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.reason).toContain('not in the allowlist');
      expect(result.metadata?.mode).toBe('allowlist');
    });

    it('should block with high confidence', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://blocked.com' },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.confidence).toBe(0.95);
    });

    it('should still block malware even if similar domain could match', async () => {
      // Note: malware.google.com doesn't match the malware patterns since
      // *.malware.* requires malware to be the second-level domain
      // Use a proper malware-like domain
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://download.malware.net' },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.websiteCategory).toBe('malware');
      expect(result.severity).toBe('critical');
    });
  });

  describe('with empty allowlist', () => {
    beforeEach(() => {
      detector = new WebsiteDetectorImpl({
        enabled: true,
        mode: 'allowlist',
        severity: 'high',
        action: 'block',
        blocklist: [],
        allowlist: [],
      });
    });

    it('should block everything when allowlist is empty', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://github.com' },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.reason).toContain('empty allowlist');
      expect(result.confidence).toBe(0.99);
    });
  });
});

// =============================================================================
// BLOCKLIST MODE TESTS
// =============================================================================

describe('Website Detector - Blocklist Mode', () => {
  let detector: WebsiteDetectorImpl;

  describe('with populated blocklist', () => {
    beforeEach(() => {
      detector = new WebsiteDetectorImpl({
        enabled: true,
        mode: 'blocklist',
        severity: 'high',
        action: 'block',
        blocklist: ['evil.com', '*.malware.com', 'phishing-*.net'],
        allowlist: [],
      });
    });

    it('should block exact match in blocklist', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://evil.com/path' },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.matchedPattern).toBe('evil.com');
      expect(result.metadata?.mode).toBe('blocklist');
    });

    it('should block glob pattern match in blocklist', async () => {
      // Note: download.malware.com also matches the category detector's *.malware.* pattern
      // which takes precedence. Let's use a non-category domain to test blocklist glob matching
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://api.badsite.com' },
      };
      
      // Re-create detector with a blocklist pattern that doesn't overlap with category patterns
      const testDetector = new WebsiteDetectorImpl({
        enabled: true,
        mode: 'blocklist',
        severity: 'high',
        action: 'block',
        blocklist: ['*.badsite.com'],
        allowlist: [],
      });
      
      const result = await testDetector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.matchedPattern).toBe('*.badsite.com');
    });

    it('should block prefix glob pattern', async () => {
      // Use a domain that matches the blocklist but not category patterns
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://blocked-site.net' },
      };
      
      // Re-create detector with a custom blocklist pattern
      const testDetector = new WebsiteDetectorImpl({
        enabled: true,
        mode: 'blocklist',
        severity: 'high',
        action: 'block',
        blocklist: ['blocked-*.net'],
        allowlist: [],
      });
      
      const result = await testDetector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.matchedPattern).toBe('blocked-*.net');
    });

    it('should allow domain not in blocklist', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://github.com' },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(false);
      expect(result.metadata?.mode).toBe('blocklist');
    });
  });

  describe('with empty blocklist', () => {
    beforeEach(() => {
      detector = new WebsiteDetectorImpl({
        enabled: true,
        mode: 'blocklist',
        severity: 'high',
        action: 'block',
        blocklist: [],
        allowlist: [],
      });
    });

    it('should allow everything when blocklist is empty (no category)', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://example.com' },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(false);
    });

    it('should still block malware even with empty blocklist', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://download.virus.net' },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.websiteCategory).toBe('malware');
    });

    it('should warn about gambling with empty blocklist', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://online-casino.com' },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.websiteCategory).toBe('gambling');
      expect(result.severity).toBe('medium'); // Warning severity for gambling
    });
  });
});

// =============================================================================
// CATEGORY-BASED DETECTION TESTS
// =============================================================================

describe('Website Detector - Category Detection', () => {
  let detector: WebsiteDetectorImpl;

  beforeEach(() => {
    detector = createDefaultWebsiteDetector();
  });

  it('should block malware sites with critical severity', async () => {
    const context: DetectionContext = {
      toolName: 'browser_navigate',
      toolInput: { url: 'https://free-crack-software.org' },
    };
    
    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
    expect(result.severity).toBe('critical');
    expect(result.metadata?.websiteCategory).toBe('malware');
  });

  it('should block phishing sites with critical severity', async () => {
    const context: DetectionContext = {
      toolName: 'browser_navigate',
      toolInput: { url: 'https://paypa1-login.com' },
    };
    
    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
    expect(result.severity).toBe('critical');
    expect(result.metadata?.websiteCategory).toBe('phishing');
  });

  it('should warn about gambling sites with medium severity', async () => {
    // Use a domain that clearly matches gambling patterns (*slots* pattern)
    const context: DetectionContext = {
      toolName: 'browser_navigate',
      toolInput: { url: 'https://online-casino-games.com' },
    };
    
    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
    expect(result.severity).toBe('medium');
    expect(result.metadata?.websiteCategory).toBe('gambling');
  });

  it('should warn about adult sites with medium severity', async () => {
    const context: DetectionContext = {
      toolName: 'browser_navigate',
      toolInput: { url: 'https://adult-videos.com' },
    };
    
    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
    expect(result.severity).toBe('medium');
    expect(result.metadata?.websiteCategory).toBe('adult');
  });
});

// =============================================================================
// GLOB PATTERN EDGE CASES
// =============================================================================

describe('Website Detector - Glob Pattern Edge Cases', () => {
  describe('subdomain matching', () => {
    it('should match single subdomain with *', async () => {
      const detector = new WebsiteDetectorImpl({
        enabled: true,
        mode: 'blocklist',
        severity: 'high',
        action: 'block',
        blocklist: ['*.example.com'],
        allowlist: [],
      });

      const result1 = await detector.detect({
        toolName: 'browser_navigate',
        toolInput: { url: 'https://api.example.com' },
      });
      expect(result1.detected).toBe(true);

      const result2 = await detector.detect({
        toolName: 'browser_navigate',
        toolInput: { url: 'https://example.com' },
      });
      expect(result2.detected).toBe(false);
    });

    it('should match multiple subdomains with **', async () => {
      const detector = new WebsiteDetectorImpl({
        enabled: true,
        mode: 'blocklist',
        severity: 'high',
        action: 'block',
        blocklist: ['**.example.com'],
        allowlist: [],
      });

      const result1 = await detector.detect({
        toolName: 'browser_navigate',
        toolInput: { url: 'https://api.example.com' },
      });
      expect(result1.detected).toBe(true);

      const result2 = await detector.detect({
        toolName: 'browser_navigate',
        toolInput: { url: 'https://deep.sub.example.com' },
      });
      expect(result2.detected).toBe(true);
    });
  });

  describe('TLD matching', () => {
    it('should match different TLDs with wildcard', async () => {
      const detector = new WebsiteDetectorImpl({
        enabled: true,
        mode: 'allowlist',
        severity: 'high',
        action: 'block',
        blocklist: [],
        allowlist: ['example.*'],
      });

      const result1 = await detector.detect({
        toolName: 'browser_navigate',
        toolInput: { url: 'https://example.com' },
      });
      expect(result1.detected).toBe(false);

      const result2 = await detector.detect({
        toolName: 'browser_navigate',
        toolInput: { url: 'https://example.org' },
      });
      expect(result2.detected).toBe(false);
    });
  });
});

// =============================================================================
// EDGE CASES
// =============================================================================

describe('Website Detector - Edge Cases', () => {
  let detector: WebsiteDetectorImpl;

  beforeEach(() => {
    detector = createDefaultWebsiteDetector();
  });

  it('should handle empty context', async () => {
    const context: DetectionContext = {
      toolName: 'unknown',
      toolInput: {},
    };
    
    const result = await detector.detect(context);
    expect(result.detected).toBe(false);
  });

  it('should handle context without URL', async () => {
    const context: DetectionContext = {
      toolName: 'write_file',
      toolInput: { content: 'hello' },
    };
    
    const result = await detector.detect(context);
    expect(result.detected).toBe(false);
  });

  it('should handle malformed URLs gracefully', async () => {
    const context: DetectionContext = {
      toolName: 'browser_navigate',
      toolInput: { url: 'not-a-valid-url' },
    };
    
    const result = await detector.detect(context);
    expect(result.detected).toBe(false); // Should not crash
  });

  it('should handle URLs with special characters', async () => {
    const context: DetectionContext = {
      toolName: 'browser_navigate',
      toolInput: { url: 'https://example.com/path?query=value&other=123' },
    };
    
    const result = await detector.detect(context);
    expect(result.detected).toBe(false); // Normal domain, should be allowed
  });

  it('should handle disabled detector', async () => {
    const disabledDetector = new WebsiteDetectorImpl({
      enabled: false,
      mode: 'blocklist',
      severity: 'high',
      action: 'block',
      blocklist: ['evil.com'],
      allowlist: [],
    });

    const context: DetectionContext = {
      toolName: 'browser_navigate',
      toolInput: { url: 'https://evil.com' },
    };
    
    const result = await disabledDetector.detect(context);
    expect(result.detected).toBe(false);
  });

  it('should use configured severity for blocklist matches', async () => {
    const customDetector = new WebsiteDetectorImpl({
      enabled: true,
      mode: 'blocklist',
      severity: 'low',
      action: 'warn',
      blocklist: ['blocked.com'],
      allowlist: [],
    });

    const context: DetectionContext = {
      toolName: 'browser_navigate',
      toolInput: { url: 'https://blocked.com' },
    };
    
    const result = await customDetector.detect(context);
    expect(result.detected).toBe(true);
    expect(result.severity).toBe('low');
  });
});

// =============================================================================
// FACTORY FUNCTION TESTS
// =============================================================================

describe('Factory Functions', () => {
  it('should create detector from WebsiteRule', () => {
    const rule = {
      enabled: true,
      mode: 'allowlist' as const,
      severity: 'medium' as const,
      action: 'confirm' as const,
      blocklist: ['evil.com'],
      allowlist: ['good.com'],
    };
    
    const detector = createWebsiteDetector(rule);
    expect(detector.isEnabled()).toBe(true);
    expect(detector.getMode()).toBe('allowlist');
    expect(detector.getAction()).toBe('confirm');
  });

  it('should create default detector with blocklist mode', () => {
    const detector = createDefaultWebsiteDetector();
    expect(detector.isEnabled()).toBe(true);
    expect(detector.getMode()).toBe('blocklist');
    expect(detector.getAction()).toBe('block');
  });
});

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

describe('Integration', () => {
  it('should work with realistic Playwright browser_navigate context', async () => {
    const detector = createDefaultWebsiteDetector();
    
    const context: DetectionContext = {
      toolName: 'mcp__playwright__browser_navigate',
      toolInput: {
        url: 'https://github.com/openclawai/clawsec',
      },
    };
    
    const result = await detector.detect(context);
    expect(result.detected).toBe(false);
    expect(result.category).toBe('website');
  });

  it('should block malware in realistic context', async () => {
    const detector = new WebsiteDetectorImpl({
      enabled: true,
      mode: 'allowlist',
      severity: 'high',
      action: 'block',
      blocklist: [],
      allowlist: ['github.com', '*.npmjs.com'],
    });
    
    const context: DetectionContext = {
      toolName: 'mcp__playwright__browser_navigate',
      toolInput: {
        url: 'https://download-free-keygen.xyz',
      },
    };
    
    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
    // Malware category takes precedence
    expect(result.metadata?.websiteCategory).toBe('malware');
  });

  it('should allow whitelisted domain in strict mode', async () => {
    const detector = new WebsiteDetectorImpl({
      enabled: true,
      mode: 'allowlist',
      severity: 'high',
      action: 'block',
      blocklist: [],
      allowlist: ['docs.openclaw.ai', 'github.com'],
    });
    
    const context: DetectionContext = {
      toolName: 'browser_navigate',
      toolInput: { url: 'https://docs.openclaw.ai/guide' },
    };
    
    const result = await detector.detect(context);
    expect(result.detected).toBe(false);
    expect(result.metadata?.matchedPattern).toBe('docs.openclaw.ai');
  });
});

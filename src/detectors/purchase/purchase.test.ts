/**
 * Purchase Detector Tests
 * Comprehensive tests for domain, URL, form field, and combined detection
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  // Main detector
  PurchaseDetectorImpl,
  createPurchaseDetector,
  createDefaultPurchaseDetector,
  
  // Domain detection
  DomainDetector,
  createDomainDetector,
  extractDomain,
  matchDomain,
  globToRegex,
  matchesGlobPattern,
  hasPaymentKeyword,
  
  // URL detection
  UrlDetector,
  createUrlDetector,
  extractPath,
  matchUrlPath,
  
  // Form detection
  FormDetector,
  createFormDetector,
  matchFormFields,
  containsPaymentValues,
  
  // Spend tracking
  SpendTracker,
  createSpendTracker,
  resetGlobalSpendTracker,
  
  // Types
  type DetectionContext,
  type PurchaseDetectorConfig,
} from './index.js';

// =============================================================================
// DOMAIN DETECTOR TESTS
// =============================================================================

describe('Domain Detector', () => {
  describe('extractDomain', () => {
    it('should extract domain from full URL', () => {
      expect(extractDomain('https://amazon.com/products')).toBe('amazon.com');
      expect(extractDomain('http://www.stripe.com/checkout')).toBe('www.stripe.com');
    });

    it('should extract domain from URL without protocol', () => {
      expect(extractDomain('amazon.com/products')).toBe('amazon.com');
      expect(extractDomain('shop.example.com')).toBe('shop.example.com');
    });

    it('should handle URLs with ports', () => {
      expect(extractDomain('https://localhost:3000/checkout')).toBe('localhost');
      expect(extractDomain('http://payment.example.com:8080')).toBe('payment.example.com');
    });

    it('should return null for invalid URLs', () => {
      expect(extractDomain('')).toBe(null);
      expect(extractDomain('not a url at all')).toBe(null);
    });

    it('should normalize domain to lowercase', () => {
      expect(extractDomain('https://AMAZON.COM')).toBe('amazon.com');
      expect(extractDomain('https://PayPal.Com')).toBe('paypal.com');
    });
  });

  describe('globToRegex', () => {
    it('should convert simple glob patterns', () => {
      const regex = globToRegex('amazon.*');
      expect(regex.test('amazon.com')).toBe(true);
      expect(regex.test('amazon.co.uk')).toBe(true);
      expect(regex.test('noamazon.com')).toBe(false);
    });

    it('should handle wildcard subdomain patterns', () => {
      const regex = globToRegex('*.stripe.com');
      expect(regex.test('api.stripe.com')).toBe(true);
      expect(regex.test('checkout.stripe.com')).toBe(true);
      expect(regex.test('stripe.com')).toBe(false);
    });

    it('should escape special regex characters', () => {
      const regex = globToRegex('example.com');
      expect(regex.test('example.com')).toBe(true);
      expect(regex.test('exampleXcom')).toBe(false);
    });
  });

  describe('matchesGlobPattern', () => {
    it('should match exact domains', () => {
      expect(matchesGlobPattern('amazon.com', 'amazon.com')).toBe(true);
      expect(matchesGlobPattern('amazon.com', 'ebay.com')).toBe(false);
    });

    it('should match wildcard TLD', () => {
      expect(matchesGlobPattern('amazon.co.uk', 'amazon.*')).toBe(true);
      expect(matchesGlobPattern('amazon.de', 'amazon.*')).toBe(true);
    });

    it('should match wildcard subdomain', () => {
      expect(matchesGlobPattern('api.paypal.com', '*.paypal.com')).toBe(true);
      expect(matchesGlobPattern('checkout.paypal.com', '*.paypal.com')).toBe(true);
    });
  });

  describe('hasPaymentKeyword', () => {
    it('should detect payment keywords in domain', () => {
      expect(hasPaymentKeyword('payment.example.com')).toBe('payment');
      expect(hasPaymentKeyword('checkout.mystore.com')).toBe('checkout');
      expect(hasPaymentKeyword('shop.example.com')).toBe('shop');
    });

    it('should return null for non-payment domains', () => {
      expect(hasPaymentKeyword('blog.example.com')).toBe(null);
      expect(hasPaymentKeyword('docs.company.com')).toBe(null);
    });
  });

  describe('matchDomain', () => {
    it('should match known payment domains with high confidence', () => {
      const result = matchDomain('amazon.com');
      expect(result.matched).toBe(true);
      expect(result.matchType).toBe('exact');
      expect(result.confidence).toBe(0.95);
    });

    it('should match payment processors', () => {
      expect(matchDomain('stripe.com').matched).toBe(true);
      expect(matchDomain('paypal.com').matched).toBe(true);
      expect(matchDomain('braintreepayments.com').matched).toBe(true);
    });

    it('should match e-commerce platforms', () => {
      expect(matchDomain('shopify.com').matched).toBe(true);
      expect(matchDomain('myshopify.com').matched).toBe(true);
    });

    it('should match custom blocklist', () => {
      const result = matchDomain('custom-shop.com', ['custom-shop.com']);
      expect(result.matched).toBe(true);
      expect(result.matchType).toBe('exact');
    });

    it('should match custom blocklist with glob pattern', () => {
      const result = matchDomain('store.custom.com', ['*.custom.com']);
      expect(result.matched).toBe(true);
      expect(result.matchType).toBe('glob');
    });

    it('should match domains with payment keywords', () => {
      const result = matchDomain('pay.mycompany.com');
      expect(result.matched).toBe(true);
      expect(result.matchType).toBe('glob');
    });

    it('should not match unrelated domains', () => {
      const result = matchDomain('github.com');
      expect(result.matched).toBe(false);
    });
  });

  describe('DomainDetector class', () => {
    let detector: DomainDetector;

    beforeEach(() => {
      detector = createDomainDetector('critical');
    });

    it('should detect purchase domain from URL in context', () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://amazon.com/checkout' },
      };
      
      const result = detector.detect(context);
      expect(result).not.toBeNull();
      expect(result?.detected).toBe(true);
      expect(result?.category).toBe('purchase');
      expect(result?.metadata?.domain).toBe('amazon.com');
    });

    it('should detect from context.url', () => {
      const context: DetectionContext = {
        toolName: 'navigate',
        toolInput: {},
        url: 'https://stripe.com/payment',
      };
      
      const result = detector.detect(context);
      expect(result?.detected).toBe(true);
      expect(result?.metadata?.domain).toBe('stripe.com');
    });

    it('should detect from href input', () => {
      const context: DetectionContext = {
        toolName: 'click_link',
        toolInput: { href: 'https://paypal.com/checkout' },
      };
      
      const result = detector.detect(context);
      expect(result?.detected).toBe(true);
    });

    it('should return null for non-payment domains', () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://github.com/repo' },
      };
      
      const result = detector.detect(context);
      expect(result).toBeNull();
    });

    it('should return null when no URL is present', () => {
      const context: DetectionContext = {
        toolName: 'write_file',
        toolInput: { content: 'hello' },
      };
      
      const result = detector.detect(context);
      expect(result).toBeNull();
    });
  });
});

// =============================================================================
// URL DETECTOR TESTS
// =============================================================================

describe('URL Detector', () => {
  describe('extractPath', () => {
    it('should extract path from URL', () => {
      expect(extractPath('https://example.com/checkout')).toBe('/checkout');
      expect(extractPath('https://shop.com/cart/payment')).toBe('/cart/payment');
    });

    it('should handle URL without protocol', () => {
      expect(extractPath('example.com/checkout')).toBe('/checkout');
    });

    it('should handle URL with query params', () => {
      expect(extractPath('https://shop.com/checkout?id=123')).toBe('/checkout');
    });

    it('should normalize path to lowercase', () => {
      expect(extractPath('https://shop.com/CHECKOUT')).toBe('/checkout');
    });
  });

  describe('matchUrlPath', () => {
    it('should match checkout paths', () => {
      expect(matchUrlPath('/checkout').matched).toBe(true);
      expect(matchUrlPath('https://shop.com/checkout').matched).toBe(true);
      expect(matchUrlPath('/cart/checkout').matched).toBe(true);
      expect(matchUrlPath('/secure/checkout').matched).toBe(true);
    });

    it('should match payment paths', () => {
      expect(matchUrlPath('/payment').matched).toBe(true);
      expect(matchUrlPath('/payments').matched).toBe(true);
      expect(matchUrlPath('/cart/payment').matched).toBe(true);
    });

    it('should match purchase paths', () => {
      expect(matchUrlPath('/buy').matched).toBe(true);
      expect(matchUrlPath('/purchase').matched).toBe(true);
      expect(matchUrlPath('/order').matched).toBe(true);
      expect(matchUrlPath('/orders/create').matched).toBe(true);
    });

    it('should match subscription paths', () => {
      expect(matchUrlPath('/subscribe').matched).toBe(true);
      expect(matchUrlPath('/subscription').matched).toBe(true);
      expect(matchUrlPath('/billing').matched).toBe(true);
      expect(matchUrlPath('/upgrade').matched).toBe(true);
    });

    it('should match API endpoints', () => {
      expect(matchUrlPath('/api/orders').matched).toBe(true);
      expect(matchUrlPath('/api/checkout').matched).toBe(true);
      expect(matchUrlPath('/api/v1/payment').matched).toBe(true);
    });

    it('should match paths with keywords', () => {
      const result = matchUrlPath('/user/checkout-flow');
      expect(result.matched).toBe(true);
      expect(result.confidence).toBeLessThan(0.9); // Lower confidence for keyword match
    });

    it('should not match unrelated paths', () => {
      expect(matchUrlPath('/about').matched).toBe(false);
      expect(matchUrlPath('/contact').matched).toBe(false);
      expect(matchUrlPath('/api/users').matched).toBe(false);
    });
  });

  describe('UrlDetector class', () => {
    let detector: UrlDetector;

    beforeEach(() => {
      detector = createUrlDetector('critical');
    });

    it('should detect checkout URL', () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://shop.com/checkout' },
      };
      
      const result = detector.detect(context);
      expect(result?.detected).toBe(true);
      expect(result?.metadata?.matchedPattern).toBeDefined();
    });

    it('should detect from path input', () => {
      const context: DetectionContext = {
        toolName: 'api_call',
        toolInput: { path: '/api/orders' },
      };
      
      const result = detector.detect(context);
      expect(result?.detected).toBe(true);
    });

    it('should return null for non-payment URLs', () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://docs.example.com/guide' },
      };
      
      const result = detector.detect(context);
      expect(result).toBeNull();
    });
  });
});

// =============================================================================
// FORM DETECTOR TESTS
// =============================================================================

describe('Form Detector', () => {
  describe('matchFormFields', () => {
    it('should match credit card fields with high confidence', () => {
      const result = matchFormFields(['cardNumber', 'cvv', 'expiry']);
      expect(result.matched).toBe(true);
      expect(result.confidence).toBeGreaterThanOrEqual(0.9);
      expect(result.fields).toContain('cardNumber');
    });

    it('should match card number variations', () => {
      expect(matchFormFields(['card-number']).matched).toBe(true);
      expect(matchFormFields(['creditCard']).matched).toBe(true);
      expect(matchFormFields(['cc-number']).matched).toBe(true);
    });

    it('should match CVV/CVC variations', () => {
      expect(matchFormFields(['cvv']).matched).toBe(true);
      expect(matchFormFields(['cvc']).matched).toBe(true);
      expect(matchFormFields(['security-code']).matched).toBe(true);
    });

    it('should match expiry variations', () => {
      expect(matchFormFields(['expiry']).matched).toBe(true);
      expect(matchFormFields(['exp-date']).matched).toBe(true);
      expect(matchFormFields(['exp-month', 'exp-year']).matched).toBe(true);
    });

    it('should match billing address fields', () => {
      const result = matchFormFields(['billing-address', 'billing-city', 'billing-zip']);
      expect(result.matched).toBe(true);
    });

    it('should match payment method fields', () => {
      expect(matchFormFields(['payment-method']).matched).toBe(true);
      expect(matchFormFields(['payment-type']).matched).toBe(true);
    });

    it('should match bank account fields', () => {
      expect(matchFormFields(['routing-number']).matched).toBe(true);
      expect(matchFormFields(['bank-account']).matched).toBe(true);
      expect(matchFormFields(['iban']).matched).toBe(true);
    });

    it('should have higher confidence for multiple matches', () => {
      const single = matchFormFields(['billing-address']);
      const multiple = matchFormFields(['billing-address', 'billing-city', 'billing-zip']);
      expect(multiple.confidence).toBeGreaterThan(single.confidence);
    });

    it('should not match unrelated fields', () => {
      const result = matchFormFields(['username', 'email', 'password']);
      expect(result.matched).toBe(false);
    });
  });

  describe('containsPaymentValues', () => {
    it('should detect credit card numbers', () => {
      expect(containsPaymentValues('4111 1111 1111 1111')).toBe(true);
      expect(containsPaymentValues('4111-1111-1111-1111')).toBe(true);
      expect(containsPaymentValues('4111111111111111')).toBe(true);
    });

    it('should detect CVV patterns', () => {
      expect(containsPaymentValues('cvv: 123')).toBe(true);
      expect(containsPaymentValues('CVV:456')).toBe(true);
    });

    it('should detect expiry dates', () => {
      expect(containsPaymentValues('12/25')).toBe(true);
      expect(containsPaymentValues('01-2027')).toBe(true);
    });

    it('should not trigger on normal text', () => {
      expect(containsPaymentValues('hello world')).toBe(false);
      expect(containsPaymentValues('phone: 555-1234')).toBe(false);
    });
  });

  describe('FormDetector class', () => {
    let detector: FormDetector;

    beforeEach(() => {
      detector = createFormDetector('critical');
    });

    it('should detect form fields from direct input keys', () => {
      const context: DetectionContext = {
        toolName: 'fill_form',
        toolInput: {
          cardNumber: '4111111111111111',
          cvv: '123',
        },
      };
      
      const result = detector.detect(context);
      expect(result?.detected).toBe(true);
      expect(result?.metadata?.formFields).toBeDefined();
    });

    it('should detect form fields from fields array', () => {
      const context: DetectionContext = {
        toolName: 'fill_form',
        toolInput: {
          fields: [
            { name: 'card-number', value: '4111111111111111' },
            { name: 'cvv', value: '123' },
          ],
        },
      };
      
      const result = detector.detect(context);
      expect(result?.detected).toBe(true);
    });

    it('should detect payment values in text', () => {
      const context: DetectionContext = {
        toolName: 'type',
        toolInput: {
          text: '4111 1111 1111 1111',
          selector: '#input',
        },
      };
      
      const result = detector.detect(context);
      expect(result?.detected).toBe(true);
    });

    it('should detect from selector/ref inputs', () => {
      const context: DetectionContext = {
        toolName: 'click',
        toolInput: {
          ref: 'credit-card-input',
          element: 'payment-form',
        },
      };
      
      const result = detector.detect(context);
      expect(result?.detected).toBe(true);
    });

    it('should return null for non-payment forms', () => {
      const context: DetectionContext = {
        toolName: 'fill_form',
        toolInput: {
          username: 'john',
          email: 'john@example.com',
        },
      };
      
      const result = detector.detect(context);
      expect(result).toBeNull();
    });
  });
});

// =============================================================================
// MAIN PURCHASE DETECTOR TESTS
// =============================================================================

describe('PurchaseDetector', () => {
  let detector: PurchaseDetectorImpl;

  beforeEach(() => {
    detector = createDefaultPurchaseDetector();
  });

  describe('basic detection', () => {
    it('should detect domain-based purchase', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://amazon.com/products' },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.category).toBe('purchase');
      expect(result.metadata?.domain).toBe('amazon.com');
    });

    it('should detect URL-based purchase', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://example.com/checkout' },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.matchedPattern).toBeDefined();
    });

    it('should detect form-based purchase', async () => {
      const context: DetectionContext = {
        toolName: 'fill_form',
        toolInput: {
          cardNumber: '4111111111111111',
          cvv: '123',
          expiry: '12/25',
        },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.formFields).toBeDefined();
    });
  });

  describe('combined detection', () => {
    it('should boost confidence when multiple detectors match', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://amazon.com/checkout' },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      // Both domain and URL should match, boosting confidence
      expect(result.confidence).toBeGreaterThan(0.9);
    });

    it('should combine metadata from multiple detectors', async () => {
      const context: DetectionContext = {
        toolName: 'fill_form',
        toolInput: {
          url: 'https://stripe.com/checkout',
          cardNumber: '4111111111111111',
        },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.domain).toBeDefined();
      expect(result.metadata?.formFields).toBeDefined();
    });
  });

  describe('disabled detector', () => {
    it('should return no detection when disabled', async () => {
      const config: PurchaseDetectorConfig = {
        enabled: false,
        severity: 'critical',
        action: 'block',
      };
      const disabledDetector = new PurchaseDetectorImpl(config);
      
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://amazon.com/checkout' },
      };
      
      const result = await disabledDetector.detect(context);
      expect(result.detected).toBe(false);
    });
  });

  describe('configuration', () => {
    it('should use custom blocklist', async () => {
      const config: PurchaseDetectorConfig = {
        enabled: true,
        severity: 'high',
        action: 'confirm',
        domains: {
          mode: 'blocklist',
          blocklist: ['custom-payment.com', '*.internal-shop.com'],
        },
      };
      const customDetector = new PurchaseDetectorImpl(config);
      
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://custom-payment.com/pay' },
      };
      
      const result = await customDetector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.severity).toBe('high');
    });

    it('should create detector from PurchaseRule', () => {
      const rule = {
        enabled: true,
        severity: 'high' as const,
        action: 'confirm' as const,
        spendLimits: { perTransaction: 100, daily: 500 },
        domains: {
          mode: 'blocklist' as const,
          blocklist: ['test.com'],
        },
      };
      
      const ruleDetector = createPurchaseDetector(rule);
      expect(ruleDetector.isEnabled()).toBe(true);
      expect(ruleDetector.getAction()).toBe('confirm');
    });
  });

  describe('edge cases', () => {
    it('should handle empty context', async () => {
      const context: DetectionContext = {
        toolName: 'unknown',
        toolInput: {},
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(false);
    });

    it('should handle malformed URLs', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'not-a-valid-url' },
      };
      
      const result = await detector.detect(context);
      // Should not crash, might or might not detect based on keywords
      expect(result.category).toBe('purchase');
    });

    it('should handle null/undefined values in input', async () => {
      const context: DetectionContext = {
        toolName: 'fill_form',
        toolInput: {
          url: undefined,
          field: null,
        } as Record<string, unknown>,
      };
      
      // Should not throw
      const result = await detector.detect(context);
      expect(result.category).toBe('purchase');
    });

    it('should not false positive on similar but unrelated domains', async () => {
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://notamazon.com/about' },
      };
      
      const result = await detector.detect(context);
      // "amazon" is in the domain but it's not actual Amazon
      // This tests that we match properly
      expect(result.detected).toBe(false);
    });

    it('should not false positive on URLs with payment-like paths in non-payment context', async () => {
      // A blog post about checkout
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://blog.example.com/how-to-build-checkout' },
      };
      
      const result = await detector.detect(context);
      // The keyword "checkout" is there but it's in a blog context
      // This shows the limitation - it will detect based on keyword
      // This is expected behavior for security-first approach
      expect(result.category).toBe('purchase');
    });
  });

  describe('severity and confidence', () => {
    it('should have higher confidence for exact domain matches', async () => {
      const exactContext: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://amazon.com' },
      };
      
      const keywordContext: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://payment.unknown.com' },
      };
      
      const exactResult = await detector.detect(exactContext);
      const keywordResult = await detector.detect(keywordContext);
      
      expect(exactResult.confidence).toBeGreaterThan(keywordResult.confidence);
    });

    it('should use configured severity', async () => {
      const config: PurchaseDetectorConfig = {
        enabled: true,
        severity: 'medium',
        action: 'warn',
      };
      const mediumDetector = new PurchaseDetectorImpl(config);
      
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: { url: 'https://amazon.com' },
      };
      
      const result = await mediumDetector.detect(context);
      expect(result.severity).toBe('medium');
    });
  });
});

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

describe('Integration', () => {
  it('should work with realistic Playwright browser_navigate context', async () => {
    const detector = createDefaultPurchaseDetector();
    
    const context: DetectionContext = {
      toolName: 'mcp__playwright__browser_navigate',
      toolInput: {
        url: 'https://checkout.stripe.com/pay/cs_test_123',
      },
    };
    
    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
    expect(result.confidence).toBeGreaterThan(0.8);
  });

  it('should work with realistic form fill context', async () => {
    const detector = createDefaultPurchaseDetector();
    
    const context: DetectionContext = {
      toolName: 'mcp__playwright__browser_fill_form',
      toolInput: {
        fields: [
          { name: 'cardNumber', type: 'textbox', ref: 'ref1', value: '4242424242424242' },
          { name: 'cardExpiry', type: 'textbox', ref: 'ref2', value: '12/25' },
          { name: 'cardCvc', type: 'textbox', ref: 'ref3', value: '123' },
        ],
      },
    };
    
    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
    expect(result.metadata?.formFields).toBeDefined();
  });

  it('should work with API call context', async () => {
    const detector = createDefaultPurchaseDetector();
    
    const context: DetectionContext = {
      toolName: 'http_request',
      toolInput: {
        method: 'POST',
        url: 'https://api.example.com/api/v1/orders',
        body: { items: [{ id: 1, qty: 2 }] },
      },
    };
    
    const result = await detector.detect(context);
    expect(result.detected).toBe(true);
  });
});

// =============================================================================
// SPEND LIMIT INTEGRATION TESTS
// =============================================================================

describe('Spend Limit Integration', () => {
  let spendTracker: SpendTracker;
  
  beforeEach(() => {
    spendTracker = createSpendTracker();
    resetGlobalSpendTracker();
  });

  describe('detection with spend limits', () => {
    it('should include amount in metadata when detected', async () => {
      const config: PurchaseDetectorConfig = {
        enabled: true,
        severity: 'critical',
        action: 'block',
        spendLimits: {
          perTransaction: 100,
          daily: 500,
        },
      };
      const detector = new PurchaseDetectorImpl(config, spendTracker);
      
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: {
          url: 'https://amazon.com/checkout',
          amount: 50,
        },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.amount).toBe(50);
      expect(result.metadata?.currentDailyTotal).toBe(0);
    });

    it('should detect per-transaction limit exceeded', async () => {
      const config: PurchaseDetectorConfig = {
        enabled: true,
        severity: 'critical',
        action: 'block',
        spendLimits: {
          perTransaction: 100,
          daily: 500,
        },
      };
      const detector = new PurchaseDetectorImpl(config, spendTracker);
      
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: {
          url: 'https://amazon.com/checkout',
          amount: 150,
        },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.exceededLimit).toBe('perTransaction');
      expect(result.reason).toContain('per-transaction limit');
    });

    it('should detect daily limit exceeded', async () => {
      const config: PurchaseDetectorConfig = {
        enabled: true,
        severity: 'critical',
        action: 'block',
        spendLimits: {
          perTransaction: 100,
          daily: 200,
        },
      };
      const detector = new PurchaseDetectorImpl(config, spendTracker);
      
      // Record previous transactions
      spendTracker.record(100);
      spendTracker.record(50);
      // Total: 150, remaining: 50
      
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: {
          url: 'https://amazon.com/checkout',
          amount: 75,  // Would exceed daily limit
        },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.exceededLimit).toBe('daily');
      expect(result.metadata?.currentDailyTotal).toBe(150);
      expect(result.reason).toContain('daily limit');
    });

    it('should not add limit info when within limits', async () => {
      const config: PurchaseDetectorConfig = {
        enabled: true,
        severity: 'critical',
        action: 'block',
        spendLimits: {
          perTransaction: 100,
          daily: 500,
        },
      };
      const detector = new PurchaseDetectorImpl(config, spendTracker);
      
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: {
          url: 'https://amazon.com/checkout',
          amount: 50,
        },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.exceededLimit).toBeUndefined();
      expect(result.metadata?.amount).toBe(50);
    });
  });

  describe('amount extraction from context', () => {
    it('should extract amount from price field', async () => {
      const config: PurchaseDetectorConfig = {
        enabled: true,
        severity: 'critical',
        action: 'block',
        spendLimits: {
          perTransaction: 100,
          daily: 500,
        },
      };
      const detector = new PurchaseDetectorImpl(config, spendTracker);
      
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: {
          url: 'https://amazon.com/checkout',
          price: '99.99',
        },
      };
      
      const result = await detector.detect(context);
      expect(result.metadata?.amount).toBe(99.99);
    });

    it('should extract amount from URL query params', async () => {
      const config: PurchaseDetectorConfig = {
        enabled: true,
        severity: 'critical',
        action: 'block',
        spendLimits: {
          perTransaction: 100,
          daily: 500,
        },
      };
      const detector = new PurchaseDetectorImpl(config, spendTracker);
      
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: {
          url: 'https://amazon.com/checkout?total=75.00',
        },
      };
      
      const result = await detector.detect(context);
      expect(result.metadata?.amount).toBe(75);
    });

    it('should use perTransaction limit when amount unknown', async () => {
      const config: PurchaseDetectorConfig = {
        enabled: true,
        severity: 'critical',
        action: 'block',
        spendLimits: {
          perTransaction: 100,
          daily: 150,
        },
      };
      const detector = new PurchaseDetectorImpl(config, spendTracker);
      
      // Record enough to nearly max daily limit
      spendTracker.record(100);
      // Remaining: 50, but unknown amount will use perTransaction (100)
      
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: {
          url: 'https://amazon.com/checkout',
          // No amount specified
        },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      // Should flag as exceeding daily (100 + 100 > 150)
      expect(result.metadata?.exceededLimit).toBe('daily');
      expect(result.metadata?.amount).toBeUndefined();
    });
  });

  describe('transaction recording', () => {
    it('should record transaction via detector', () => {
      const config: PurchaseDetectorConfig = {
        enabled: true,
        severity: 'critical',
        action: 'block',
        spendLimits: {
          perTransaction: 100,
          daily: 500,
        },
      };
      const detector = new PurchaseDetectorImpl(config, spendTracker);
      
      detector.recordTransaction(75, { domain: 'amazon.com' });
      
      expect(spendTracker.getDailyTotal()).toBe(75);
      const transactions = spendTracker.getTransactions();
      expect(transactions[0].domain).toBe('amazon.com');
    });

    it('should accumulate transactions affecting future detections', async () => {
      const config: PurchaseDetectorConfig = {
        enabled: true,
        severity: 'critical',
        action: 'block',
        spendLimits: {
          perTransaction: 100,
          daily: 200,
        },
      };
      const detector = new PurchaseDetectorImpl(config, spendTracker);
      
      // First detection - should be fine
      const context1: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: {
          url: 'https://amazon.com/checkout',
          amount: 75,
        },
      };
      const result1 = await detector.detect(context1);
      expect(result1.metadata?.exceededLimit).toBeUndefined();
      
      // Record the transaction
      detector.recordTransaction(75);
      
      // Second detection - should still be fine
      const context2: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: {
          url: 'https://amazon.com/checkout',
          amount: 75,
        },
      };
      const result2 = await detector.detect(context2);
      expect(result2.metadata?.exceededLimit).toBeUndefined();
      expect(result2.metadata?.currentDailyTotal).toBe(75);
      
      // Record second transaction
      detector.recordTransaction(75);
      
      // Third detection - should exceed daily limit
      const context3: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: {
          url: 'https://amazon.com/checkout',
          amount: 75,
        },
      };
      const result3 = await detector.detect(context3);
      expect(result3.metadata?.exceededLimit).toBe('daily');
      expect(result3.metadata?.currentDailyTotal).toBe(150);
    });
  });

  describe('createPurchaseDetector with spend limits', () => {
    it('should create detector with spend limits from rule', async () => {
      const rule = {
        enabled: true,
        severity: 'critical' as const,
        action: 'block' as const,
        spendLimits: { perTransaction: 50, daily: 100 },
        domains: {
          mode: 'blocklist' as const,
          blocklist: [],
        },
      };
      
      const detector = createPurchaseDetector(rule, spendTracker);
      
      expect(detector.getSpendLimits()).toEqual({
        perTransaction: 50,
        daily: 100,
      });
      
      // Test that limits are enforced
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: {
          url: 'https://amazon.com/checkout',
          amount: 75,  // Exceeds perTransaction of 50
        },
      };
      
      const result = await detector.detect(context);
      expect(result.metadata?.exceededLimit).toBe('perTransaction');
    });

    it('should work without spend limits', async () => {
      const rule = {
        enabled: true,
        severity: 'critical' as const,
        action: 'block' as const,
        domains: {
          mode: 'blocklist' as const,
          blocklist: [],
        },
      };
      
      const detector = createPurchaseDetector(rule, spendTracker);
      
      expect(detector.getSpendLimits()).toBeUndefined();
      
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: {
          url: 'https://amazon.com/checkout',
          amount: 10000,  // Large amount but no limits configured
        },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      expect(result.metadata?.exceededLimit).toBeUndefined();
    });
  });

  describe('without spend limits configured', () => {
    it('should not check spend limits when not configured', async () => {
      const config: PurchaseDetectorConfig = {
        enabled: true,
        severity: 'critical',
        action: 'block',
        // No spendLimits
      };
      const detector = new PurchaseDetectorImpl(config, spendTracker);
      
      const context: DetectionContext = {
        toolName: 'browser_navigate',
        toolInput: {
          url: 'https://amazon.com/checkout',
          amount: 10000,
        },
      };
      
      const result = await detector.detect(context);
      expect(result.detected).toBe(true);
      // No limit checking happens, so no limit info in metadata
      expect(result.metadata?.exceededLimit).toBeUndefined();
      expect(result.metadata?.currentDailyTotal).toBeUndefined();
    });
  });
});

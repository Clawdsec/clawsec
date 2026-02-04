/**
 * Spend Tracker Tests
 * Comprehensive tests for spend limit tracking functionality
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  SpendTracker,
  createSpendTracker,
  getGlobalSpendTracker,
  resetGlobalSpendTracker,
  extractAmount,
  extractAmountFromInput,
  type SpendRecord,
  type SpendLimitResult,
} from './spend-tracker.js';
import type { SpendLimits } from '../../config/index.js';

// =============================================================================
// AMOUNT EXTRACTION TESTS
// =============================================================================

describe('Amount Extraction', () => {
  describe('extractAmount', () => {
    it('should extract dollar amounts', () => {
      expect(extractAmount('$100')).toBe(100);
      expect(extractAmount('$100.00')).toBe(100);
      expect(extractAmount('$99.99')).toBe(99.99);
      expect(extractAmount('$ 50')).toBe(50);
    });

    it('should extract amounts with thousands separators', () => {
      expect(extractAmount('$1,000')).toBe(1000);
      expect(extractAmount('$1,000.00')).toBe(1000);
      expect(extractAmount('$10,000.50')).toBe(10000.5);
    });

    it('should extract other currency amounts', () => {
      expect(extractAmount('€100')).toBe(100);
      expect(extractAmount('£50.00')).toBe(50);
      expect(extractAmount('¥1000')).toBe(1000);
    });

    it('should extract labeled amounts', () => {
      expect(extractAmount('amount=100')).toBe(100);
      expect(extractAmount('price: 99.99')).toBe(99.99);
      expect(extractAmount('total=50.00')).toBe(50);
      expect(extractAmount('TOTAL: 75')).toBe(75);
    });

    it('should extract amounts with currency codes', () => {
      expect(extractAmount('100 USD')).toBe(100);
      expect(extractAmount('99.99 EUR')).toBe(99.99);
      expect(extractAmount('50.00 GBP')).toBe(50);
    });

    it('should extract plain decimal numbers', () => {
      expect(extractAmount('99.99')).toBe(99.99);
      expect(extractAmount('100.00')).toBe(100);
    });

    it('should return null for invalid inputs', () => {
      expect(extractAmount('')).toBe(null);
      expect(extractAmount('not a number')).toBe(null);
      expect(extractAmount('abc')).toBe(null);
    });

    it('should return null for non-string inputs', () => {
      expect(extractAmount(null as unknown as string)).toBe(null);
      expect(extractAmount(undefined as unknown as string)).toBe(null);
    });

    it('should not extract negative amounts', () => {
      expect(extractAmount('-100')).toBe(null);
      expect(extractAmount('$-50')).toBe(null);
    });
  });

  describe('extractAmountFromInput', () => {
    it('should extract from amount field', () => {
      expect(extractAmountFromInput({ amount: 100 })).toBe(100);
      expect(extractAmountFromInput({ amount: '99.99' })).toBe(99.99);
      expect(extractAmountFromInput({ amount: '$50' })).toBe(50);
    });

    it('should extract from price field', () => {
      expect(extractAmountFromInput({ price: 75 })).toBe(75);
      expect(extractAmountFromInput({ price: '25.00' })).toBe(25);
    });

    it('should extract from total field', () => {
      expect(extractAmountFromInput({ total: 150 })).toBe(150);
      expect(extractAmountFromInput({ grandTotal: '200' })).toBe(200);
    });

    it('should prioritize amount fields over others', () => {
      expect(extractAmountFromInput({ amount: 100, price: 50 })).toBe(100);
    });

    it('should extract from URL query parameters', () => {
      expect(extractAmountFromInput({ 
        url: 'https://shop.com/checkout?amount=50' 
      })).toBe(50);
      expect(extractAmountFromInput({ 
        url: 'https://shop.com/pay?price=99.99' 
      })).toBe(99.99);
    });

    it('should extract from nested data objects', () => {
      expect(extractAmountFromInput({ 
        data: { amount: 75 } 
      })).toBe(75);
      expect(extractAmountFromInput({ 
        body: { total: 100 } 
      })).toBe(100);
      expect(extractAmountFromInput({ 
        formData: { price: '50.00' } 
      })).toBe(50);
    });

    it('should extract from Playwright form fields array', () => {
      expect(extractAmountFromInput({
        fields: [
          { name: 'cardNumber', value: '4111111111111111' },
          { name: 'amount', value: '99.99' },
        ],
      })).toBe(99.99);
    });

    it('should extract currency patterns from string values', () => {
      expect(extractAmountFromInput({
        text: 'Pay $150.00 now',
      })).toBe(150);
    });

    it('should not extract from URL/selector fields', () => {
      // These fields should be skipped for currency pattern scanning
      expect(extractAmountFromInput({
        url: 'https://example.com',
        selector: '#payment-form',
      })).toBe(null);
    });

    it('should return null when no amount found', () => {
      expect(extractAmountFromInput({})).toBe(null);
      expect(extractAmountFromInput({ username: 'john' })).toBe(null);
      expect(extractAmountFromInput({ email: 'test@example.com' })).toBe(null);
    });

    it('should handle invalid URL gracefully', () => {
      expect(extractAmountFromInput({ 
        url: 'not-a-valid-url' 
      })).toBe(null);
    });
  });
});

// =============================================================================
// SPEND TRACKER CORE TESTS
// =============================================================================

describe('SpendTracker', () => {
  let tracker: SpendTracker;
  const defaultLimits: SpendLimits = {
    perTransaction: 100,
    daily: 500,
  };

  beforeEach(() => {
    tracker = createSpendTracker();
  });

  describe('record', () => {
    it('should record a transaction', () => {
      tracker.record(50);
      
      const transactions = tracker.getTransactions();
      expect(transactions.length).toBe(1);
      expect(transactions[0].amount).toBe(50);
      expect(transactions[0].approved).toBe(true);
    });

    it('should record with metadata', () => {
      tracker.record(75, { transactionId: 'test-123', domain: 'example.com' });
      
      const transactions = tracker.getTransactions();
      expect(transactions[0].transactionId).toBe('test-123');
      expect(transactions[0].domain).toBe('example.com');
    });

    it('should generate transaction ID if not provided', () => {
      tracker.record(50);
      
      const transactions = tracker.getTransactions();
      expect(transactions[0].transactionId).toMatch(/^txn_/);
    });

    it('should record multiple transactions', () => {
      tracker.record(25);
      tracker.record(50);
      tracker.record(75);
      
      const transactions = tracker.getTransactions();
      expect(transactions.length).toBe(3);
    });
  });

  describe('checkLimits', () => {
    describe('per-transaction limit', () => {
      it('should allow transaction within per-transaction limit', () => {
        const result = tracker.checkLimits(50, defaultLimits);
        
        expect(result.allowed).toBe(true);
        expect(result.exceededLimit).toBeUndefined();
      });

      it('should allow transaction exactly at per-transaction limit', () => {
        const result = tracker.checkLimits(100, defaultLimits);
        
        expect(result.allowed).toBe(true);
      });

      it('should block transaction exceeding per-transaction limit', () => {
        const result = tracker.checkLimits(150, defaultLimits);
        
        expect(result.allowed).toBe(false);
        expect(result.exceededLimit).toBe('perTransaction');
        expect(result.message).toContain('per-transaction limit');
        expect(result.message).toContain('$150.00');
        expect(result.message).toContain('$100.00');
      });
    });

    describe('daily limit', () => {
      it('should allow first transaction within daily limit', () => {
        const result = tracker.checkLimits(100, defaultLimits);
        
        expect(result.allowed).toBe(true);
        expect(result.currentDailyTotal).toBe(0);
        expect(result.remainingDaily).toBe(400); // 500 - 100
      });

      it('should track daily total correctly', () => {
        tracker.record(100);
        tracker.record(150);
        
        const result = tracker.checkLimits(50, defaultLimits);
        
        expect(result.currentDailyTotal).toBe(250);
        expect(result.remainingDaily).toBe(200); // 500 - 250 - 50
      });

      it('should block transaction that would exceed daily limit', () => {
        tracker.record(100);
        tracker.record(100);
        tracker.record(100);
        tracker.record(100);
        tracker.record(50);
        // Total: 450, remaining: 50
        
        // Trying to add 75 would exceed daily limit (450 + 75 = 525 > 500)
        // But 75 is within per-transaction limit (100)
        const result = tracker.checkLimits(75, defaultLimits);
        
        expect(result.allowed).toBe(false);
        expect(result.exceededLimit).toBe('daily');
        expect(result.message).toContain('daily limit');
        expect(result.currentDailyTotal).toBe(450);
      });

      it('should allow transaction that fills daily limit exactly', () => {
        tracker.record(100);
        tracker.record(100);
        tracker.record(100);
        tracker.record(100);
        // Total: 400
        
        const result = tracker.checkLimits(100, defaultLimits);
        
        expect(result.allowed).toBe(true);
        expect(result.remainingDaily).toBe(0);
      });

      it('should block when daily limit already exceeded', () => {
        tracker.record(500);
        
        const result = tracker.checkLimits(1, defaultLimits);
        
        expect(result.allowed).toBe(false);
        expect(result.exceededLimit).toBe('daily');
      });
    });

    describe('limit priority', () => {
      it('should check per-transaction limit before daily limit', () => {
        // Even with plenty of daily budget, should fail per-transaction
        const result = tracker.checkLimits(200, defaultLimits);
        
        expect(result.allowed).toBe(false);
        expect(result.exceededLimit).toBe('perTransaction');
      });
    });
  });

  describe('getDailyTotal', () => {
    it('should return 0 for no transactions', () => {
      expect(tracker.getDailyTotal()).toBe(0);
    });

    it('should sum all transactions from today', () => {
      tracker.record(50);
      tracker.record(75);
      tracker.record(25);
      
      expect(tracker.getDailyTotal()).toBe(150);
    });

    it('should only include approved transactions', () => {
      tracker.record(100);
      // All recorded transactions are approved by default
      expect(tracker.getDailyTotal()).toBe(100);
    });
  });

  describe('getTransactions', () => {
    it('should return empty array for no transactions', () => {
      expect(tracker.getTransactions()).toEqual([]);
    });

    it('should return transactions sorted by timestamp (newest first)', async () => {
      // Use fake timers to ensure different timestamps
      vi.useFakeTimers();
      const baseTime = Date.now();
      
      vi.setSystemTime(baseTime);
      tracker.record(50, { transactionId: 'first' });
      
      vi.setSystemTime(baseTime + 1000);
      tracker.record(75, { transactionId: 'second' });
      
      vi.setSystemTime(baseTime + 2000);
      tracker.record(25, { transactionId: 'third' });
      
      const transactions = tracker.getTransactions(baseTime - 1000);
      expect(transactions.length).toBe(3);
      expect(transactions[0].transactionId).toBe('third');
      expect(transactions[1].transactionId).toBe('second');
      expect(transactions[2].transactionId).toBe('first');
      
      vi.useRealTimers();
    });

    it('should filter by since parameter', () => {
      const now = Date.now();
      tracker.record(50);
      
      // Get transactions from the future - should be empty
      const futureTransactions = tracker.getTransactions(now + 10000);
      expect(futureTransactions.length).toBe(0);
      
      // Get transactions from the past - should include all
      const pastTransactions = tracker.getTransactions(now - 10000);
      expect(pastTransactions.length).toBe(1);
    });
  });

  describe('reset', () => {
    it('should clear all transactions', () => {
      tracker.record(50);
      tracker.record(75);
      
      expect(tracker.getTransactions().length).toBe(2);
      
      tracker.reset();
      
      expect(tracker.getTransactions().length).toBe(0);
      expect(tracker.getDailyTotal()).toBe(0);
    });
  });

  describe('24-hour boundary (daily reset)', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should not include transactions from previous day in daily total', () => {
      // Set time to 11 PM
      const now = new Date();
      now.setHours(23, 0, 0, 0);
      vi.setSystemTime(now);
      
      tracker.record(100);
      expect(tracker.getDailyTotal()).toBe(100);
      
      // Advance to next day (2 hours later)
      vi.advanceTimersByTime(2 * 60 * 60 * 1000);
      
      // Daily total should reset to 0 (transaction was yesterday)
      expect(tracker.getDailyTotal()).toBe(0);
      
      // Record new transaction today
      tracker.record(50);
      expect(tracker.getDailyTotal()).toBe(50);
    });

    it('should include only today\'s transactions in limit check', () => {
      // Set time to late evening
      const now = new Date();
      now.setHours(23, 30, 0, 0);
      vi.setSystemTime(now);
      
      // Max out daily limit
      tracker.record(500);
      expect(tracker.checkLimits(1, defaultLimits).allowed).toBe(false);
      
      // Advance to next day
      vi.advanceTimersByTime(60 * 60 * 1000); // 1 hour
      
      // Should now be allowed (new day)
      expect(tracker.checkLimits(100, defaultLimits).allowed).toBe(true);
    });
  });

  describe('auto-cleanup', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should clean up old transactions after cleanup interval', () => {
      // Create tracker with short cleanup interval (1 second)
      const shortCleanupTracker = new SpendTracker(1000);
      
      // Record a transaction
      shortCleanupTracker.record(100);
      
      // Advance time past 24 hours
      vi.advanceTimersByTime(25 * 60 * 60 * 1000);
      
      // Trigger cleanup by calling a method
      shortCleanupTracker.checkLimits(1, defaultLimits);
      
      // Old transaction should be cleaned up
      expect(shortCleanupTracker.getTransactions(0).length).toBe(0);
    });
  });
});

// =============================================================================
// GLOBAL SPEND TRACKER TESTS
// =============================================================================

describe('Global SpendTracker', () => {
  beforeEach(() => {
    resetGlobalSpendTracker();
  });

  it('should return the same instance', () => {
    const tracker1 = getGlobalSpendTracker();
    const tracker2 = getGlobalSpendTracker();
    
    expect(tracker1).toBe(tracker2);
  });

  it('should persist transactions across calls', () => {
    const tracker1 = getGlobalSpendTracker();
    tracker1.record(100);
    
    const tracker2 = getGlobalSpendTracker();
    expect(tracker2.getDailyTotal()).toBe(100);
  });

  it('should reset properly', () => {
    const tracker = getGlobalSpendTracker();
    tracker.record(100);
    
    resetGlobalSpendTracker();
    
    const newTracker = getGlobalSpendTracker();
    expect(newTracker.getDailyTotal()).toBe(0);
  });

  it('should create new instance after reset', () => {
    const tracker1 = getGlobalSpendTracker();
    resetGlobalSpendTracker();
    const tracker2 = getGlobalSpendTracker();
    
    expect(tracker1).not.toBe(tracker2);
  });
});

// =============================================================================
// ACCUMULATION TESTS
// =============================================================================

describe('Transaction Accumulation', () => {
  let tracker: SpendTracker;
  const limits: SpendLimits = {
    perTransaction: 100,
    daily: 300,
  };

  beforeEach(() => {
    tracker = createSpendTracker();
  });

  it('should correctly track multiple small transactions', () => {
    // Each transaction within per-transaction limit
    // But together they approach daily limit
    
    tracker.record(50);
    expect(tracker.checkLimits(50, limits).allowed).toBe(true);
    expect(tracker.checkLimits(50, limits).currentDailyTotal).toBe(50);
    
    tracker.record(50);
    expect(tracker.checkLimits(50, limits).allowed).toBe(true);
    expect(tracker.checkLimits(50, limits).currentDailyTotal).toBe(100);
    
    tracker.record(50);
    expect(tracker.checkLimits(50, limits).allowed).toBe(true);
    expect(tracker.checkLimits(50, limits).currentDailyTotal).toBe(150);
    
    tracker.record(50);
    expect(tracker.checkLimits(50, limits).allowed).toBe(true);
    expect(tracker.checkLimits(50, limits).currentDailyTotal).toBe(200);
    
    tracker.record(50);
    // Now at 250, another 50 would hit 300 exactly
    expect(tracker.checkLimits(50, limits).allowed).toBe(true);
    expect(tracker.checkLimits(50, limits).remainingDaily).toBe(0);
    
    tracker.record(50);
    // Now at 300, any more should be blocked
    expect(tracker.checkLimits(1, limits).allowed).toBe(false);
    expect(tracker.checkLimits(1, limits).exceededLimit).toBe('daily');
  });

  it('should handle mixed transaction sizes', () => {
    tracker.record(80); // Within per-txn, total: 80
    tracker.record(90); // Within per-txn, total: 170
    tracker.record(70); // Within per-txn, total: 240
    
    // Remaining: 60
    expect(tracker.checkLimits(60, limits).allowed).toBe(true);
    expect(tracker.checkLimits(61, limits).allowed).toBe(false);
  });
});

// =============================================================================
// EDGE CASES
// =============================================================================

describe('Edge Cases', () => {
  let tracker: SpendTracker;

  beforeEach(() => {
    tracker = createSpendTracker();
  });

  it('should handle zero amount transaction', () => {
    const limits: SpendLimits = { perTransaction: 100, daily: 500 };
    const result = tracker.checkLimits(0, limits);
    
    expect(result.allowed).toBe(true);
  });

  it('should handle very small amounts', () => {
    const limits: SpendLimits = { perTransaction: 100, daily: 500 };
    const result = tracker.checkLimits(0.01, limits);
    
    expect(result.allowed).toBe(true);
  });

  it('should handle amounts with many decimal places', () => {
    tracker.record(33.333333);
    tracker.record(33.333333);
    tracker.record(33.333334);
    
    expect(tracker.getDailyTotal()).toBeCloseTo(100, 5);
  });

  it('should handle very large amounts', () => {
    const limits: SpendLimits = { perTransaction: 1000000, daily: 10000000 };
    const result = tracker.checkLimits(999999, limits);
    
    expect(result.allowed).toBe(true);
  });

  it('should handle limits of zero', () => {
    const limits: SpendLimits = { perTransaction: 0, daily: 0 };
    
    // Any amount should exceed zero limits
    expect(tracker.checkLimits(1, limits).allowed).toBe(false);
    expect(tracker.checkLimits(0.01, limits).allowed).toBe(false);
    
    // Zero amount should pass
    expect(tracker.checkLimits(0, limits).allowed).toBe(true);
  });

  it('should handle equal perTransaction and daily limits', () => {
    const limits: SpendLimits = { perTransaction: 100, daily: 100 };
    
    expect(tracker.checkLimits(100, limits).allowed).toBe(true);
    tracker.record(100);
    expect(tracker.checkLimits(1, limits).allowed).toBe(false);
  });
});

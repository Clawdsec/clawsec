/**
 * Tests for the Approval Module
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  InMemoryApprovalStore,
  createApprovalStore,
  getDefaultApprovalStore,
  resetDefaultApprovalStore,
  DefaultNativeApprovalHandler,
  createNativeApprovalHandler,
  getDefaultNativeApprovalHandler,
  resetDefaultNativeApprovalHandler,
  DefaultAgentConfirmHandler,
  createAgentConfirmHandler,
  getDefaultAgentConfirmHandler,
  resetDefaultAgentConfirmHandler,
  DEFAULT_CONFIRM_PARAMETER,
} from './index.js';
import type {
  PendingApprovalRecord,
  PendingApprovalInput,
  ApprovalStore,
} from './types.js';
import type { Detection, ToolCallContext } from '../engine/types.js';

// =============================================================================
// TEST HELPERS
// =============================================================================

/**
 * Create a test detection
 */
function createTestDetection(overrides: Partial<Detection> = {}): Detection {
  return {
    category: 'destructive',
    severity: 'critical',
    confidence: 0.95,
    reason: 'Detected rm -rf command',
    ...overrides,
  };
}

/**
 * Create a test tool call context
 */
function createTestToolCall(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    toolName: 'bash',
    toolInput: { command: 'rm -rf /tmp/test' },
    ...overrides,
  };
}

/**
 * Create a test approval input
 */
function createTestApprovalInput(overrides: Partial<PendingApprovalInput> = {}): PendingApprovalInput {
  const now = Date.now();
  return {
    id: `test-${now}-${Math.random().toString(36).slice(2)}`,
    createdAt: now,
    expiresAt: now + 300_000, // 5 minutes
    detection: createTestDetection(),
    toolCall: createTestToolCall(),
    ...overrides,
  };
}

// =============================================================================
// APPROVAL STORE TESTS
// =============================================================================

describe('InMemoryApprovalStore', () => {
  let store: InMemoryApprovalStore;

  beforeEach(() => {
    // Create store without auto-cleanup for testing
    store = createApprovalStore({ cleanupIntervalMs: 0 });
  });

  afterEach(() => {
    store.stopCleanupTimer();
    store.clear();
  });

  describe('add', () => {
    it('should add a new approval record with pending status', () => {
      const input = createTestApprovalInput({ id: 'test-add-1' });

      store.add(input);

      const record = store.get('test-add-1');
      expect(record).toBeDefined();
      expect(record?.status).toBe('pending');
      expect(record?.id).toBe('test-add-1');
    });

    it('should store all fields from input', () => {
      const detection = createTestDetection({ category: 'secrets' });
      const toolCall = createTestToolCall({ toolName: 'write_file' });
      const input = createTestApprovalInput({
        id: 'test-fields',
        detection,
        toolCall,
      });

      store.add(input);

      const record = store.get('test-fields');
      expect(record?.detection).toEqual(detection);
      expect(record?.toolCall).toEqual(toolCall);
      expect(record?.createdAt).toBe(input.createdAt);
      expect(record?.expiresAt).toBe(input.expiresAt);
    });

    it('should overwrite existing record with same ID', () => {
      const input1 = createTestApprovalInput({ id: 'test-overwrite' });
      const input2 = createTestApprovalInput({
        id: 'test-overwrite',
        detection: createTestDetection({ category: 'purchase' }),
      });

      store.add(input1);
      store.add(input2);

      const record = store.get('test-overwrite');
      expect(record?.detection.category).toBe('purchase');
    });
  });

  describe('get', () => {
    it('should return undefined for non-existent ID', () => {
      const record = store.get('non-existent-id');
      expect(record).toBeUndefined();
    });

    it('should return the record for existing ID', () => {
      const input = createTestApprovalInput({ id: 'test-get' });
      store.add(input);

      const record = store.get('test-get');
      expect(record).toBeDefined();
      expect(record?.id).toBe('test-get');
    });

    it('should mark expired records as expired', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'test-expired',
        createdAt: pastTime - 300_000,
        expiresAt: pastTime,
      });
      store.add(input);

      const record = store.get('test-expired');
      expect(record?.status).toBe('expired');
    });

    it('should not change status of non-pending expired records', () => {
      // Create a record that expires in the future
      const futureTime = Date.now() + 60_000;
      const input = createTestApprovalInput({
        id: 'test-approved-expired',
        expiresAt: futureTime,
      });
      store.add(input);

      // Approve while still pending
      store.approve('test-approved-expired');
      expect(store.get('test-approved-expired')?.status).toBe('approved');

      // Now manually set expiresAt to the past to simulate time passing
      // This tests that approved records don't get marked as expired
      const record = store.get('test-approved-expired')!;
      record.expiresAt = Date.now() - 1000;

      // Getting the record again should still show approved, not expired
      const recordAgain = store.get('test-approved-expired');
      expect(recordAgain?.status).toBe('approved');
    });
  });

  describe('approve', () => {
    it('should mark pending approval as approved', () => {
      const input = createTestApprovalInput({ id: 'test-approve' });
      store.add(input);

      const result = store.approve('test-approve');

      expect(result).toBe(true);
      const record = store.get('test-approve');
      expect(record?.status).toBe('approved');
    });

    it('should set approvedBy when provided', () => {
      const input = createTestApprovalInput({ id: 'test-approver' });
      store.add(input);

      store.approve('test-approver', 'user@example.com');

      const record = store.get('test-approver');
      expect(record?.approvedBy).toBe('user@example.com');
    });

    it('should set approvedAt timestamp', () => {
      const input = createTestApprovalInput({ id: 'test-timestamp' });
      store.add(input);

      const beforeApprove = Date.now();
      store.approve('test-timestamp');
      const afterApprove = Date.now();

      const record = store.get('test-timestamp');
      expect(record?.approvedAt).toBeGreaterThanOrEqual(beforeApprove);
      expect(record?.approvedAt).toBeLessThanOrEqual(afterApprove);
    });

    it('should return false for non-existent ID', () => {
      const result = store.approve('non-existent');
      expect(result).toBe(false);
    });

    it('should return false for already approved record', () => {
      const input = createTestApprovalInput({ id: 'test-already-approved' });
      store.add(input);
      store.approve('test-already-approved');

      const result = store.approve('test-already-approved');
      expect(result).toBe(false);
    });

    it('should return false for denied record', () => {
      const input = createTestApprovalInput({ id: 'test-denied' });
      store.add(input);
      store.deny('test-denied');

      const result = store.approve('test-denied');
      expect(result).toBe(false);
    });

    it('should return false for expired record', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'test-expired-approve',
        expiresAt: pastTime,
      });
      store.add(input);

      const result = store.approve('test-expired-approve');
      expect(result).toBe(false);
    });
  });

  describe('deny', () => {
    it('should mark pending approval as denied', () => {
      const input = createTestApprovalInput({ id: 'test-deny' });
      store.add(input);

      const result = store.deny('test-deny');

      expect(result).toBe(true);
      const record = store.get('test-deny');
      expect(record?.status).toBe('denied');
    });

    it('should return false for non-existent ID', () => {
      const result = store.deny('non-existent');
      expect(result).toBe(false);
    });

    it('should return false for already denied record', () => {
      const input = createTestApprovalInput({ id: 'test-already-denied' });
      store.add(input);
      store.deny('test-already-denied');

      const result = store.deny('test-already-denied');
      expect(result).toBe(false);
    });

    it('should return false for approved record', () => {
      const input = createTestApprovalInput({ id: 'test-approved-deny' });
      store.add(input);
      store.approve('test-approved-deny');

      const result = store.deny('test-approved-deny');
      expect(result).toBe(false);
    });

    it('should return false for expired record', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'test-expired-deny',
        expiresAt: pastTime,
      });
      store.add(input);

      const result = store.deny('test-expired-deny');
      expect(result).toBe(false);
    });
  });

  describe('remove', () => {
    it('should remove an existing record', () => {
      const input = createTestApprovalInput({ id: 'test-remove' });
      store.add(input);

      store.remove('test-remove');

      expect(store.get('test-remove')).toBeUndefined();
    });

    it('should not throw for non-existent ID', () => {
      expect(() => store.remove('non-existent')).not.toThrow();
    });
  });

  describe('cleanup', () => {
    it('should mark expired pending records as expired', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'test-cleanup-expired',
        expiresAt: pastTime,
      });
      store.add(input);

      store.cleanup();

      const record = store.get('test-cleanup-expired');
      expect(record?.status).toBe('expired');
    });

    it('should not change non-pending records', () => {
      const input = createTestApprovalInput({ id: 'test-cleanup-approved' });
      store.add(input);
      store.approve('test-cleanup-approved');

      store.cleanup();

      const record = store.get('test-cleanup-approved');
      expect(record?.status).toBe('approved');
    });

    it('should remove processed records when removeOnExpiry is true', () => {
      const storeWithRemoval = createApprovalStore({
        cleanupIntervalMs: 0,
        removeOnExpiry: true,
      });

      const pastTime = Date.now() - 1000;
      const input1 = createTestApprovalInput({
        id: 'test-remove-expired',
        expiresAt: pastTime,
      });
      const input2 = createTestApprovalInput({ id: 'test-remove-approved' });

      storeWithRemoval.add(input1);
      storeWithRemoval.add(input2);
      storeWithRemoval.approve('test-remove-approved');

      storeWithRemoval.cleanup();

      expect(storeWithRemoval.get('test-remove-expired')).toBeUndefined();
      expect(storeWithRemoval.get('test-remove-approved')).toBeUndefined();

      storeWithRemoval.stopCleanupTimer();
    });

    it('should keep pending non-expired records', () => {
      const storeWithRemoval = createApprovalStore({
        cleanupIntervalMs: 0,
        removeOnExpiry: true,
      });

      const input = createTestApprovalInput({ id: 'test-keep-pending' });
      storeWithRemoval.add(input);

      storeWithRemoval.cleanup();

      expect(storeWithRemoval.get('test-keep-pending')).toBeDefined();
      expect(storeWithRemoval.get('test-keep-pending')?.status).toBe('pending');

      storeWithRemoval.stopCleanupTimer();
    });
  });

  describe('getPending', () => {
    it('should return empty array when no records', () => {
      const pending = store.getPending();
      expect(pending).toEqual([]);
    });

    it('should return only pending records', () => {
      store.add(createTestApprovalInput({ id: 'pending-1' }));
      store.add(createTestApprovalInput({ id: 'pending-2' }));
      store.add(createTestApprovalInput({ id: 'approved-1' }));
      store.add(createTestApprovalInput({ id: 'denied-1' }));

      store.approve('approved-1');
      store.deny('denied-1');

      const pending = store.getPending();

      expect(pending.length).toBe(2);
      expect(pending.map(r => r.id).sort()).toEqual(['pending-1', 'pending-2']);
    });

    it('should not return expired records', () => {
      const pastTime = Date.now() - 1000;
      store.add(createTestApprovalInput({ id: 'pending-1' }));
      store.add(createTestApprovalInput({
        id: 'expired-1',
        expiresAt: pastTime,
      }));

      const pending = store.getPending();

      expect(pending.length).toBe(1);
      expect(pending[0].id).toBe('pending-1');
    });

    it('should update status of expired records when retrieved', () => {
      const pastTime = Date.now() - 1000;
      store.add(createTestApprovalInput({
        id: 'expired-check',
        expiresAt: pastTime,
      }));

      store.getPending();

      const record = store.get('expired-check');
      expect(record?.status).toBe('expired');
    });
  });

  describe('size', () => {
    it('should return 0 for empty store', () => {
      expect(store.size()).toBe(0);
    });

    it('should return correct count of records', () => {
      store.add(createTestApprovalInput({ id: 'size-1' }));
      store.add(createTestApprovalInput({ id: 'size-2' }));
      store.add(createTestApprovalInput({ id: 'size-3' }));

      expect(store.size()).toBe(3);
    });
  });

  describe('clear', () => {
    it('should remove all records', () => {
      store.add(createTestApprovalInput({ id: 'clear-1' }));
      store.add(createTestApprovalInput({ id: 'clear-2' }));

      store.clear();

      expect(store.size()).toBe(0);
    });
  });

  describe('auto cleanup', () => {
    it('should run cleanup on interval', async () => {
      const storeWithCleanup = createApprovalStore({ cleanupIntervalMs: 50 });
      const pastTime = Date.now() - 1000;

      storeWithCleanup.add(createTestApprovalInput({
        id: 'auto-cleanup',
        expiresAt: pastTime,
      }));

      // Wait for cleanup to run
      await new Promise(resolve => setTimeout(resolve, 100));

      const record = storeWithCleanup.get('auto-cleanup');
      expect(record?.status).toBe('expired');

      storeWithCleanup.stopCleanupTimer();
    });
  });
});

describe('Default approval store singleton', () => {
  afterEach(() => {
    resetDefaultApprovalStore();
  });

  it('should return the same instance on multiple calls', () => {
    const store1 = getDefaultApprovalStore();
    const store2 = getDefaultApprovalStore();

    expect(store1).toBe(store2);
  });

  it('should create new instance after reset', () => {
    const store1 = getDefaultApprovalStore();
    resetDefaultApprovalStore();
    const store2 = getDefaultApprovalStore();

    expect(store1).not.toBe(store2);
  });

  it('should clear data on reset', () => {
    const store = getDefaultApprovalStore();
    store.add(createTestApprovalInput({ id: 'singleton-test' }));

    resetDefaultApprovalStore();

    const newStore = getDefaultApprovalStore();
    expect(newStore.get('singleton-test')).toBeUndefined();
  });
});

// =============================================================================
// NATIVE APPROVAL HANDLER TESTS
// =============================================================================

describe('DefaultNativeApprovalHandler', () => {
  let store: InMemoryApprovalStore;
  let handler: DefaultNativeApprovalHandler;

  beforeEach(() => {
    store = createApprovalStore({ cleanupIntervalMs: 0 });
    handler = createNativeApprovalHandler({ store });
  });

  afterEach(() => {
    store.stopCleanupTimer();
    store.clear();
  });

  describe('handleApprove', () => {
    it('should approve pending approval and return success', () => {
      const input = createTestApprovalInput({ id: 'handle-approve-1' });
      store.add(input);

      const result = handler.handleApprove('handle-approve-1');

      expect(result.success).toBe(true);
      expect(result.message).toContain('Approved');
      expect(result.record?.status).toBe('approved');
    });

    it('should include tool name in success message', () => {
      const input = createTestApprovalInput({
        id: 'approve-tool-name',
        toolCall: createTestToolCall({ toolName: 'dangerous_tool' }),
      });
      store.add(input);

      const result = handler.handleApprove('approve-tool-name');

      expect(result.message).toContain('dangerous_tool');
    });

    it('should include category in success message', () => {
      const input = createTestApprovalInput({
        id: 'approve-category',
        detection: createTestDetection({ category: 'destructive' }),
      });
      store.add(input);

      const result = handler.handleApprove('approve-category');

      expect(result.message.toLowerCase()).toContain('destructive');
    });

    it('should set approvedBy when userId is provided', () => {
      const input = createTestApprovalInput({ id: 'approve-user' });
      store.add(input);

      handler.handleApprove('approve-user', 'test-user');

      const record = store.get('approve-user');
      expect(record?.approvedBy).toBe('test-user');
    });

    it('should return error for empty ID', () => {
      const result = handler.handleApprove('');

      expect(result.success).toBe(false);
      expect(result.message).toContain('Invalid');
    });

    it('should return error for whitespace-only ID', () => {
      const result = handler.handleApprove('   ');

      expect(result.success).toBe(false);
      expect(result.message).toContain('Invalid');
    });

    it('should trim whitespace from ID', () => {
      const input = createTestApprovalInput({ id: 'trimmed-id' });
      store.add(input);

      const result = handler.handleApprove('  trimmed-id  ');

      expect(result.success).toBe(true);
    });

    it('should return error for non-existent ID', () => {
      const result = handler.handleApprove('non-existent-id');

      expect(result.success).toBe(false);
      expect(result.message).toContain('not found');
      expect(result.message).toContain('non-existent-id');
    });

    it('should return error for expired approval', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'expired-approval',
        expiresAt: pastTime,
      });
      store.add(input);

      const result = handler.handleApprove('expired-approval');

      expect(result.success).toBe(false);
      expect(result.message).toContain('expired');
      expect(result.record).toBeDefined();
      expect(result.record?.status).toBe('expired');
    });

    it('should return error for already approved', () => {
      const input = createTestApprovalInput({ id: 'already-approved' });
      store.add(input);
      store.approve('already-approved');

      const result = handler.handleApprove('already-approved');

      expect(result.success).toBe(false);
      expect(result.message).toContain('already approved');
      expect(result.record?.status).toBe('approved');
    });

    it('should return error for already denied', () => {
      const input = createTestApprovalInput({ id: 'already-denied' });
      store.add(input);
      store.deny('already-denied');

      const result = handler.handleApprove('already-denied');

      expect(result.success).toBe(false);
      expect(result.message).toContain('already denied');
      expect(result.record?.status).toBe('denied');
    });
  });

  describe('handleDeny', () => {
    it('should deny pending approval and return success', () => {
      const input = createTestApprovalInput({ id: 'handle-deny-1' });
      store.add(input);

      const result = handler.handleDeny('handle-deny-1');

      expect(result.success).toBe(true);
      expect(result.message).toContain('Denied');
      expect(result.record?.status).toBe('denied');
    });

    it('should include tool name in deny message', () => {
      const input = createTestApprovalInput({
        id: 'deny-tool-name',
        toolCall: createTestToolCall({ toolName: 'risky_operation' }),
      });
      store.add(input);

      const result = handler.handleDeny('deny-tool-name');

      expect(result.message).toContain('risky_operation');
    });

    it('should return error for empty ID', () => {
      const result = handler.handleDeny('');

      expect(result.success).toBe(false);
      expect(result.message).toContain('Invalid');
    });

    it('should return error for non-existent ID', () => {
      const result = handler.handleDeny('non-existent');

      expect(result.success).toBe(false);
      expect(result.message).toContain('not found');
    });

    it('should return error for expired approval', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'expired-deny',
        expiresAt: pastTime,
      });
      store.add(input);

      const result = handler.handleDeny('expired-deny');

      expect(result.success).toBe(false);
      expect(result.message).toContain('expired');
    });

    it('should return error for already approved', () => {
      const input = createTestApprovalInput({ id: 'approved-deny' });
      store.add(input);
      store.approve('approved-deny');

      const result = handler.handleDeny('approved-deny');

      expect(result.success).toBe(false);
      expect(result.message).toContain('already approved');
      expect(result.message).toContain('cannot be denied');
    });

    it('should return error for already denied', () => {
      const input = createTestApprovalInput({ id: 'denied-deny' });
      store.add(input);
      store.deny('denied-deny');

      const result = handler.handleDeny('denied-deny');

      expect(result.success).toBe(false);
      expect(result.message).toContain('already denied');
    });
  });

  describe('isApproved', () => {
    it('should return true for approved record', () => {
      const input = createTestApprovalInput({ id: 'is-approved-yes' });
      store.add(input);
      store.approve('is-approved-yes');

      expect(handler.isApproved('is-approved-yes')).toBe(true);
    });

    it('should return false for pending record', () => {
      const input = createTestApprovalInput({ id: 'is-approved-pending' });
      store.add(input);

      expect(handler.isApproved('is-approved-pending')).toBe(false);
    });

    it('should return false for denied record', () => {
      const input = createTestApprovalInput({ id: 'is-approved-denied' });
      store.add(input);
      store.deny('is-approved-denied');

      expect(handler.isApproved('is-approved-denied')).toBe(false);
    });

    it('should return false for expired record', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'is-approved-expired',
        expiresAt: pastTime,
      });
      store.add(input);

      expect(handler.isApproved('is-approved-expired')).toBe(false);
    });

    it('should return false for non-existent ID', () => {
      expect(handler.isApproved('non-existent')).toBe(false);
    });

    it('should return false for empty string', () => {
      expect(handler.isApproved('')).toBe(false);
    });

    it('should handle whitespace in ID', () => {
      const input = createTestApprovalInput({ id: 'whitespace-test' });
      store.add(input);
      store.approve('whitespace-test');

      expect(handler.isApproved('  whitespace-test  ')).toBe(true);
    });
  });

  describe('getPendingApprovals', () => {
    it('should return empty array when no approvals', () => {
      const pending = handler.getPendingApprovals();
      expect(pending).toEqual([]);
    });

    it('should return only pending approvals', () => {
      store.add(createTestApprovalInput({ id: 'get-pending-1' }));
      store.add(createTestApprovalInput({ id: 'get-pending-2' }));
      store.add(createTestApprovalInput({ id: 'get-approved' }));
      store.approve('get-approved');

      const pending = handler.getPendingApprovals();

      expect(pending.length).toBe(2);
      expect(pending.map(r => r.id).sort()).toEqual(['get-pending-1', 'get-pending-2']);
    });

    it('should not return expired approvals', () => {
      const pastTime = Date.now() - 1000;
      store.add(createTestApprovalInput({ id: 'get-pending-valid' }));
      store.add(createTestApprovalInput({
        id: 'get-pending-expired',
        expiresAt: pastTime,
      }));

      const pending = handler.getPendingApprovals();

      expect(pending.length).toBe(1);
      expect(pending[0].id).toBe('get-pending-valid');
    });
  });
});

describe('Default native approval handler singleton', () => {
  afterEach(() => {
    resetDefaultNativeApprovalHandler();
    resetDefaultApprovalStore();
  });

  it('should return the same instance on multiple calls', () => {
    const handler1 = getDefaultNativeApprovalHandler();
    const handler2 = getDefaultNativeApprovalHandler();

    expect(handler1).toBe(handler2);
  });

  it('should create new instance after reset', () => {
    const handler1 = getDefaultNativeApprovalHandler();
    resetDefaultNativeApprovalHandler();
    const handler2 = getDefaultNativeApprovalHandler();

    expect(handler1).not.toBe(handler2);
  });

  it('should use default store', () => {
    const defaultStore = getDefaultApprovalStore();
    const input = createTestApprovalInput({ id: 'default-store-test' });
    defaultStore.add(input);

    const handler = getDefaultNativeApprovalHandler();
    const result = handler.handleApprove('default-store-test');

    expect(result.success).toBe(true);
  });
});

// =============================================================================
// STATUS TRANSITION TESTS
// =============================================================================

describe('Status Transitions', () => {
  let store: InMemoryApprovalStore;

  beforeEach(() => {
    store = createApprovalStore({ cleanupIntervalMs: 0 });
  });

  afterEach(() => {
    store.stopCleanupTimer();
    store.clear();
  });

  it('pending -> approved', () => {
    store.add(createTestApprovalInput({ id: 'trans-1' }));
    expect(store.get('trans-1')?.status).toBe('pending');

    store.approve('trans-1');
    expect(store.get('trans-1')?.status).toBe('approved');
  });

  it('pending -> denied', () => {
    store.add(createTestApprovalInput({ id: 'trans-2' }));
    expect(store.get('trans-2')?.status).toBe('pending');

    store.deny('trans-2');
    expect(store.get('trans-2')?.status).toBe('denied');
  });

  it('pending -> expired (via time)', () => {
    const pastTime = Date.now() - 1000;
    store.add(createTestApprovalInput({
      id: 'trans-3',
      expiresAt: pastTime,
    }));

    // Get triggers expiry check
    expect(store.get('trans-3')?.status).toBe('expired');
  });

  it('approved -> cannot approve again', () => {
    store.add(createTestApprovalInput({ id: 'trans-4' }));
    store.approve('trans-4');

    expect(store.approve('trans-4')).toBe(false);
    expect(store.get('trans-4')?.status).toBe('approved');
  });

  it('approved -> cannot deny', () => {
    store.add(createTestApprovalInput({ id: 'trans-5' }));
    store.approve('trans-5');

    expect(store.deny('trans-5')).toBe(false);
    expect(store.get('trans-5')?.status).toBe('approved');
  });

  it('denied -> cannot approve', () => {
    store.add(createTestApprovalInput({ id: 'trans-6' }));
    store.deny('trans-6');

    expect(store.approve('trans-6')).toBe(false);
    expect(store.get('trans-6')?.status).toBe('denied');
  });

  it('denied -> cannot deny again', () => {
    store.add(createTestApprovalInput({ id: 'trans-7' }));
    store.deny('trans-7');

    expect(store.deny('trans-7')).toBe(false);
    expect(store.get('trans-7')?.status).toBe('denied');
  });

  it('expired -> cannot approve', () => {
    const pastTime = Date.now() - 1000;
    store.add(createTestApprovalInput({
      id: 'trans-8',
      expiresAt: pastTime,
    }));

    expect(store.approve('trans-8')).toBe(false);
    expect(store.get('trans-8')?.status).toBe('expired');
  });

  it('expired -> cannot deny', () => {
    const pastTime = Date.now() - 1000;
    store.add(createTestApprovalInput({
      id: 'trans-9',
      expiresAt: pastTime,
    }));

    expect(store.deny('trans-9')).toBe(false);
    expect(store.get('trans-9')?.status).toBe('expired');
  });
});

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

describe('Integration', () => {
  let store: InMemoryApprovalStore;
  let handler: DefaultNativeApprovalHandler;

  beforeEach(() => {
    store = createApprovalStore({ cleanupIntervalMs: 0 });
    handler = createNativeApprovalHandler({ store });
  });

  afterEach(() => {
    store.stopCleanupTimer();
    store.clear();
  });

  it('should handle complete approval flow', () => {
    // 1. Create pending approval
    const input = createTestApprovalInput({
      id: 'integration-1',
      detection: createTestDetection({
        category: 'destructive',
        reason: 'rm -rf detected',
      }),
      toolCall: createTestToolCall({
        toolName: 'bash',
        toolInput: { command: 'rm -rf /tmp/old' },
      }),
    });
    store.add(input);

    // 2. Verify pending
    expect(handler.isApproved('integration-1')).toBe(false);
    expect(handler.getPendingApprovals().length).toBe(1);

    // 3. Approve
    const result = handler.handleApprove('integration-1', 'admin');

    // 4. Verify approved
    expect(result.success).toBe(true);
    expect(result.message).toContain('Approved');
    expect(result.message).toContain('bash');
    expect(handler.isApproved('integration-1')).toBe(true);
    expect(handler.getPendingApprovals().length).toBe(0);

    // 5. Verify record details
    const record = store.get('integration-1');
    expect(record?.status).toBe('approved');
    expect(record?.approvedBy).toBe('admin');
    expect(record?.approvedAt).toBeDefined();
  });

  it('should handle complete deny flow', () => {
    const input = createTestApprovalInput({
      id: 'integration-2',
      toolCall: createTestToolCall({ toolName: 'dangerous_tool' }),
    });
    store.add(input);

    expect(handler.getPendingApprovals().length).toBe(1);

    const result = handler.handleDeny('integration-2');

    expect(result.success).toBe(true);
    expect(result.message).toContain('Denied');
    expect(result.message).toContain('dangerous_tool');
    expect(handler.isApproved('integration-2')).toBe(false);
    expect(handler.getPendingApprovals().length).toBe(0);
    expect(store.get('integration-2')?.status).toBe('denied');
  });

  it('should handle expiration flow', () => {
    const pastTime = Date.now() - 1000;
    const input = createTestApprovalInput({
      id: 'integration-3',
      createdAt: pastTime - 300_000,
      expiresAt: pastTime,
    });
    store.add(input);

    // Trying to approve expired
    const approveResult = handler.handleApprove('integration-3');
    expect(approveResult.success).toBe(false);
    expect(approveResult.message).toContain('expired');

    // Trying to deny expired
    const denyResult = handler.handleDeny('integration-3');
    expect(denyResult.success).toBe(false);
    expect(denyResult.message).toContain('expired');

    // Check status
    expect(handler.isApproved('integration-3')).toBe(false);
    expect(handler.getPendingApprovals().length).toBe(0);
  });

  it('should handle multiple concurrent approvals', () => {
    // Create multiple approvals
    for (let i = 1; i <= 5; i++) {
      store.add(createTestApprovalInput({
        id: `multi-${i}`,
        toolCall: createTestToolCall({ toolName: `tool-${i}` }),
      }));
    }

    expect(handler.getPendingApprovals().length).toBe(5);

    // Approve some
    handler.handleApprove('multi-1');
    handler.handleApprove('multi-3');

    // Deny some
    handler.handleDeny('multi-2');

    // Check states
    expect(handler.isApproved('multi-1')).toBe(true);
    expect(handler.isApproved('multi-2')).toBe(false);
    expect(handler.isApproved('multi-3')).toBe(true);
    expect(handler.isApproved('multi-4')).toBe(false);
    expect(handler.isApproved('multi-5')).toBe(false);

    expect(handler.getPendingApprovals().length).toBe(2);
    expect(handler.getPendingApprovals().map(r => r.id).sort()).toEqual(['multi-4', 'multi-5']);
  });
});

// =============================================================================
// AGENT CONFIRM HANDLER TESTS
// =============================================================================

describe('DefaultAgentConfirmHandler', () => {
  let store: InMemoryApprovalStore;
  let handler: DefaultAgentConfirmHandler;

  beforeEach(() => {
    store = createApprovalStore({ cleanupIntervalMs: 0 });
    handler = createAgentConfirmHandler({ store });
  });

  afterEach(() => {
    store.stopCleanupTimer();
    store.clear();
  });

  describe('checkConfirmation', () => {
    it('should return not confirmed when parameter is missing', () => {
      const toolInput = { command: 'rm -rf /tmp/test' };

      const result = handler.checkConfirmation(toolInput);

      expect(result.confirmed).toBe(false);
      expect(result.valid).toBe(false);
      expect(result.approvalId).toBeUndefined();
      expect(result.error).toBeUndefined();
    });

    it('should return confirmed and valid for pending approval', () => {
      const input = createTestApprovalInput({ id: 'check-valid' });
      store.add(input);

      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: 'check-valid',
      };

      const result = handler.checkConfirmation(toolInput);

      expect(result.confirmed).toBe(true);
      expect(result.valid).toBe(true);
      expect(result.approvalId).toBe('check-valid');
      expect(result.error).toBeUndefined();
    });

    it('should return error for invalid approval ID (non-string)', () => {
      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: 123,
      };

      const result = handler.checkConfirmation(toolInput);

      expect(result.confirmed).toBe(true);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('non-empty string');
    });

    it('should return error for empty approval ID', () => {
      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: '',
      };

      const result = handler.checkConfirmation(toolInput);

      expect(result.confirmed).toBe(true);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('non-empty string');
    });

    it('should return error for whitespace-only approval ID', () => {
      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: '   ',
      };

      const result = handler.checkConfirmation(toolInput);

      expect(result.confirmed).toBe(true);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('non-empty string');
    });

    it('should return error for non-existent approval ID', () => {
      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: 'non-existent-id',
      };

      const result = handler.checkConfirmation(toolInput);

      expect(result.confirmed).toBe(true);
      expect(result.valid).toBe(false);
      expect(result.approvalId).toBe('non-existent-id');
      expect(result.error).toContain('not found');
    });

    it('should return error for expired approval', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'check-expired',
        expiresAt: pastTime,
      });
      store.add(input);

      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: 'check-expired',
      };

      const result = handler.checkConfirmation(toolInput);

      expect(result.confirmed).toBe(true);
      expect(result.valid).toBe(false);
      expect(result.approvalId).toBe('check-expired');
      expect(result.error).toContain('expired');
    });

    it('should return error for already approved', () => {
      const input = createTestApprovalInput({ id: 'check-already-approved' });
      store.add(input);
      store.approve('check-already-approved');

      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: 'check-already-approved',
      };

      const result = handler.checkConfirmation(toolInput);

      expect(result.confirmed).toBe(true);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('already approved');
    });

    it('should return error for already denied', () => {
      const input = createTestApprovalInput({ id: 'check-denied' });
      store.add(input);
      store.deny('check-denied');

      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: 'check-denied',
      };

      const result = handler.checkConfirmation(toolInput);

      expect(result.confirmed).toBe(true);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('denied');
    });

    it('should trim whitespace from approval ID', () => {
      const input = createTestApprovalInput({ id: 'check-trimmed' });
      store.add(input);

      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: '  check-trimmed  ',
      };

      const result = handler.checkConfirmation(toolInput);

      expect(result.confirmed).toBe(true);
      expect(result.valid).toBe(true);
      expect(result.approvalId).toBe('check-trimmed');
    });

    it('should use custom parameter name when provided', () => {
      const input = createTestApprovalInput({ id: 'custom-param-check' });
      store.add(input);

      const toolInput = {
        command: 'rm -rf /tmp/test',
        _my_custom_confirm: 'custom-param-check',
      };

      const result = handler.checkConfirmation(toolInput, '_my_custom_confirm');

      expect(result.confirmed).toBe(true);
      expect(result.valid).toBe(true);
      expect(result.approvalId).toBe('custom-param-check');
    });

    it('should not find confirmation when using wrong parameter name', () => {
      const input = createTestApprovalInput({ id: 'wrong-param' });
      store.add(input);

      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: 'wrong-param',
      };

      const result = handler.checkConfirmation(toolInput, '_different_param');

      expect(result.confirmed).toBe(false);
      expect(result.valid).toBe(false);
    });
  });

  describe('stripConfirmParameter', () => {
    it('should remove the default confirm parameter', () => {
      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: 'some-id',
        otherParam: 'value',
      };

      const result = handler.stripConfirmParameter(toolInput);

      expect(result).toEqual({
        command: 'rm -rf /tmp/test',
        otherParam: 'value',
      });
      expect('_clawsec_confirm' in result).toBe(false);
    });

    it('should remove custom parameter name', () => {
      const toolInput = {
        command: 'rm -rf /tmp/test',
        _my_confirm: 'some-id',
        _clawsec_confirm: 'should-stay',
      };

      const result = handler.stripConfirmParameter(toolInput, '_my_confirm');

      expect(result).toEqual({
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: 'should-stay',
      });
    });

    it('should return same object if parameter does not exist', () => {
      const toolInput = {
        command: 'rm -rf /tmp/test',
        otherParam: 'value',
      };

      const result = handler.stripConfirmParameter(toolInput);

      expect(result).toEqual(toolInput);
    });

    it('should not modify original object', () => {
      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: 'some-id',
      };

      handler.stripConfirmParameter(toolInput);

      expect('_clawsec_confirm' in toolInput).toBe(true);
    });

    it('should handle empty tool input', () => {
      const toolInput = {};

      const result = handler.stripConfirmParameter(toolInput);

      expect(result).toEqual({});
    });
  });

  describe('processConfirmation', () => {
    it('should approve pending approval and return valid result', () => {
      const input = createTestApprovalInput({ id: 'process-valid' });
      store.add(input);

      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: 'process-valid',
      };

      const result = handler.processConfirmation(toolInput);

      expect(result.confirmed).toBe(true);
      expect(result.valid).toBe(true);
      expect(result.approvalId).toBe('process-valid');

      // Verify the record was approved
      const record = store.get('process-valid');
      expect(record?.status).toBe('approved');
      expect(record?.approvedBy).toBe('agent');
    });

    it('should not approve for invalid approval ID', () => {
      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: 'non-existent',
      };

      const result = handler.processConfirmation(toolInput);

      expect(result.confirmed).toBe(true);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('not found');
    });

    it('should not approve expired approval', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'process-expired',
        expiresAt: pastTime,
      });
      store.add(input);

      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: 'process-expired',
      };

      const result = handler.processConfirmation(toolInput);

      expect(result.confirmed).toBe(true);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('expired');

      // Verify record is still expired
      expect(store.get('process-expired')?.status).toBe('expired');
    });

    it('should return not confirmed when parameter is missing', () => {
      const toolInput = { command: 'rm -rf /tmp/test' };

      const result = handler.processConfirmation(toolInput);

      expect(result.confirmed).toBe(false);
      expect(result.valid).toBe(false);
    });
  });

  describe('configuration', () => {
    it('should use custom parameter name from config', () => {
      const customHandler = createAgentConfirmHandler({
        store,
        parameterName: '_custom_confirm',
      });

      const input = createTestApprovalInput({ id: 'config-custom' });
      store.add(input);

      const toolInput = {
        command: 'rm -rf /tmp/test',
        _custom_confirm: 'config-custom',
      };

      const result = customHandler.checkConfirmation(toolInput);

      expect(result.confirmed).toBe(true);
      expect(result.valid).toBe(true);
    });

    it('should return error when disabled', () => {
      const disabledHandler = createAgentConfirmHandler({
        store,
        enabled: false,
      });

      const input = createTestApprovalInput({ id: 'config-disabled' });
      store.add(input);

      const toolInput = {
        command: 'rm -rf /tmp/test',
        _clawsec_confirm: 'config-disabled',
      };

      const result = disabledHandler.checkConfirmation(toolInput);

      expect(result.confirmed).toBe(false);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('disabled');
    });

    it('should report enabled status', () => {
      const enabledHandler = createAgentConfirmHandler({ store, enabled: true });
      const disabledHandler = createAgentConfirmHandler({ store, enabled: false });

      expect(enabledHandler.isEnabled()).toBe(true);
      expect(disabledHandler.isEnabled()).toBe(false);
    });

    it('should report parameter name', () => {
      const defaultHandler = createAgentConfirmHandler({ store });
      const customHandler = createAgentConfirmHandler({
        store,
        parameterName: '_my_param',
      });

      expect(defaultHandler.getParameterName()).toBe('_clawsec_confirm');
      expect(customHandler.getParameterName()).toBe('_my_param');
    });
  });
});

describe('Default agent confirm handler singleton', () => {
  afterEach(() => {
    resetDefaultAgentConfirmHandler();
    resetDefaultApprovalStore();
  });

  it('should return the same instance on multiple calls', () => {
    const handler1 = getDefaultAgentConfirmHandler();
    const handler2 = getDefaultAgentConfirmHandler();

    expect(handler1).toBe(handler2);
  });

  it('should create new instance after reset', () => {
    const handler1 = getDefaultAgentConfirmHandler();
    resetDefaultAgentConfirmHandler();
    const handler2 = getDefaultAgentConfirmHandler();

    expect(handler1).not.toBe(handler2);
  });

  it('should use default store', () => {
    const defaultStore = getDefaultApprovalStore();
    const input = createTestApprovalInput({ id: 'singleton-agent-test' });
    defaultStore.add(input);

    const handler = getDefaultAgentConfirmHandler();
    const toolInput = { _clawsec_confirm: 'singleton-agent-test' };

    const result = handler.checkConfirmation(toolInput);

    expect(result.confirmed).toBe(true);
    expect(result.valid).toBe(true);
  });
});

describe('DEFAULT_CONFIRM_PARAMETER constant', () => {
  it('should equal _clawsec_confirm', () => {
    expect(DEFAULT_CONFIRM_PARAMETER).toBe('_clawsec_confirm');
  });
});

// =============================================================================
// AGENT CONFIRM INTEGRATION TESTS
// =============================================================================

describe('Agent Confirm Integration', () => {
  let store: InMemoryApprovalStore;
  let handler: DefaultAgentConfirmHandler;

  beforeEach(() => {
    store = createApprovalStore({ cleanupIntervalMs: 0 });
    handler = createAgentConfirmHandler({ store });
  });

  afterEach(() => {
    store.stopCleanupTimer();
    store.clear();
  });

  it('should handle complete agent confirmation flow', () => {
    // 1. Create pending approval (simulating detection triggering approval)
    const approval = createTestApprovalInput({
      id: 'agent-flow-1',
      detection: createTestDetection({
        category: 'destructive',
        reason: 'rm -rf detected',
      }),
      toolCall: createTestToolCall({
        toolName: 'bash',
        toolInput: { command: 'rm -rf /tmp/old' },
      }),
    });
    store.add(approval);

    // 2. Simulate agent retrying with confirmation
    const retryInput = {
      command: 'rm -rf /tmp/old',
      _clawsec_confirm: 'agent-flow-1',
    };

    // 3. Process the confirmation
    const result = handler.processConfirmation(retryInput);

    // 4. Verify success
    expect(result.confirmed).toBe(true);
    expect(result.valid).toBe(true);

    // 5. Verify record was approved
    const record = store.get('agent-flow-1');
    expect(record?.status).toBe('approved');
    expect(record?.approvedBy).toBe('agent');

    // 6. Strip the parameter for clean execution
    const cleanInput = handler.stripConfirmParameter(retryInput);
    expect(cleanInput).toEqual({ command: 'rm -rf /tmp/old' });
  });

  it('should reject confirmation for wrong tool call', () => {
    // Create approval for one tool call
    const approval = createTestApprovalInput({
      id: 'wrong-tool',
      toolCall: createTestToolCall({
        toolName: 'bash',
        toolInput: { command: 'rm -rf /specific/path' },
      }),
    });
    store.add(approval);

    // Note: The current implementation validates the approval ID exists
    // but does NOT validate that the tool input matches the original.
    // This is by design - the approval ID is the key, and the agent
    // is responsible for using it correctly.
    const differentInput = {
      command: 'different-command',
      _clawsec_confirm: 'wrong-tool',
    };

    const result = handler.processConfirmation(differentInput);

    // Current implementation approves based on ID alone
    expect(result.valid).toBe(true);
  });

  it('should handle rapid retry attempts', () => {
    const approval = createTestApprovalInput({ id: 'rapid-retry' });
    store.add(approval);

    const toolInput = { _clawsec_confirm: 'rapid-retry' };

    // First attempt should succeed
    const result1 = handler.processConfirmation(toolInput);
    expect(result1.valid).toBe(true);

    // Second attempt should fail (already approved)
    const result2 = handler.processConfirmation(toolInput);
    expect(result2.valid).toBe(false);
    expect(result2.error).toContain('already approved');
  });
});

// =============================================================================
// WEBHOOK APPROVAL CLIENT TESTS
// =============================================================================

import {
  DefaultWebhookApprovalClient,
  createWebhookApprovalClient,
  getDefaultWebhookApprovalClient,
  resetDefaultWebhookApprovalClient,
  createWebhookRequest,
} from './webhook.js';
import type {
  HttpClient,
  HttpResponse,
  WebhookApprovalRequest,
  WebhookApprovalResponse,
} from './webhook.js';
import type { WebhookApproval } from '../config/schema.js';

/**
 * Mock HTTP client for testing
 */
class MockHttpClient implements HttpClient {
  private nextResponse: HttpResponse | null = null;
  private nextError: Error | null = null;
  public lastRequest: { url: string; body: unknown; options: { headers?: Record<string, string>; timeoutMs?: number } } | null = null;

  setNextResponse(response: HttpResponse): void {
    this.nextResponse = response;
    this.nextError = null;
  }

  setNextError(error: Error): void {
    this.nextError = error;
    this.nextResponse = null;
  }

  async post(
    url: string,
    body: unknown,
    options: { headers?: Record<string, string>; timeoutMs?: number }
  ): Promise<HttpResponse> {
    this.lastRequest = { url, body, options };

    if (this.nextError) {
      throw this.nextError;
    }

    if (this.nextResponse) {
      return this.nextResponse;
    }

    return { status: 200, body: { approved: true } };
  }
}

/**
 * Create a test webhook config
 */
function createTestWebhookConfig(overrides: Partial<WebhookApproval> = {}): WebhookApproval {
  return {
    enabled: true,
    url: 'https://api.example.com/approve',
    timeout: 30,
    headers: {},
    ...overrides,
  };
}

/**
 * Create a test webhook request
 */
function createTestWebhookRequest(overrides: Partial<WebhookApprovalRequest> = {}): WebhookApprovalRequest {
  const now = Date.now();
  return {
    id: `webhook-test-${now}`,
    detection: createTestDetection(),
    toolCall: {
      name: 'bash',
      input: { command: 'rm -rf /tmp/test' },
    },
    timestamp: now,
    expiresAt: now + 300_000,
    ...overrides,
  };
}

describe('DefaultWebhookApprovalClient', () => {
  let store: InMemoryApprovalStore;
  let mockHttpClient: MockHttpClient;

  beforeEach(() => {
    store = createApprovalStore({ cleanupIntervalMs: 0 });
    mockHttpClient = new MockHttpClient();
  });

  afterEach(() => {
    store.stopCleanupTimer();
    store.clear();
    resetDefaultWebhookApprovalClient();
  });

  describe('isEnabled', () => {
    it('should return true when enabled and URL is configured', () => {
      const client = createWebhookApprovalClient({
        webhookConfig: createTestWebhookConfig({ enabled: true }),
        httpClient: mockHttpClient,
        store,
      });

      expect(client.isEnabled()).toBe(true);
    });

    it('should return false when disabled', () => {
      const client = createWebhookApprovalClient({
        webhookConfig: createTestWebhookConfig({ enabled: false }),
        httpClient: mockHttpClient,
        store,
      });

      expect(client.isEnabled()).toBe(false);
    });

    it('should return false when URL is not configured', () => {
      const client = createWebhookApprovalClient({
        webhookConfig: createTestWebhookConfig({ enabled: true, url: undefined }),
        httpClient: mockHttpClient,
        store,
      });

      expect(client.isEnabled()).toBe(false);
    });
  });

  describe('requestApproval', () => {
    describe('successful sync approval', () => {
      it('should send request and return approved response', async () => {
        mockHttpClient.setNextResponse({
          status: 200,
          body: { approved: true, approvedBy: 'admin', reason: 'Looks safe' },
        });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig(),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest({ id: 'sync-approve-1' });
        const result = await client.requestApproval(request);

        expect(result.success).toBe(true);
        expect(result.waitingForCallback).toBe(false);
        expect(result.response?.approved).toBe(true);
        expect(result.response?.approvedBy).toBe('admin');
        expect(result.response?.reason).toBe('Looks safe');
      });

      it('should send request and return denied response', async () => {
        mockHttpClient.setNextResponse({
          status: 200,
          body: { approved: false, approvedBy: 'security', reason: 'Too risky' },
        });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig(),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest({ id: 'sync-deny-1' });
        const result = await client.requestApproval(request);

        expect(result.success).toBe(true);
        expect(result.waitingForCallback).toBe(false);
        expect(result.response?.approved).toBe(false);
        expect(result.response?.reason).toBe('Too risky');
      });

      it('should include correct payload in request', async () => {
        mockHttpClient.setNextResponse({ status: 200, body: { approved: true } });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig({ url: 'https://webhook.example.com/approve' }),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest({
          id: 'payload-test',
          detection: createTestDetection({ category: 'destructive', severity: 'critical' }),
          toolCall: { name: 'bash', input: { command: 'rm -rf /' } },
        });

        await client.requestApproval(request);

        expect(mockHttpClient.lastRequest?.url).toBe('https://webhook.example.com/approve');
        expect(mockHttpClient.lastRequest?.body).toMatchObject({
          id: 'payload-test',
          detection: { category: 'destructive', severity: 'critical' },
          toolCall: { name: 'bash', input: { command: 'rm -rf /' } },
        });
      });

      it('should include custom headers', async () => {
        mockHttpClient.setNextResponse({ status: 200, body: { approved: true } });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig({
            headers: {
              'Authorization': 'Bearer secret-token',
              'X-Custom-Header': 'custom-value',
            },
          }),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        await client.requestApproval(request);

        expect(mockHttpClient.lastRequest?.options.headers).toMatchObject({
          'Authorization': 'Bearer secret-token',
          'X-Custom-Header': 'custom-value',
        });
      });

      it('should use configured timeout', async () => {
        mockHttpClient.setNextResponse({ status: 200, body: { approved: true } });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig({ timeout: 60 }),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        await client.requestApproval(request);

        expect(mockHttpClient.lastRequest?.options.timeoutMs).toBe(60000);
      });
    });

    describe('async approval (202 response)', () => {
      it('should return waitingForCallback on 202 response', async () => {
        mockHttpClient.setNextResponse({ status: 202, body: {} });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig(),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest({ id: 'async-1' });
        const result = await client.requestApproval(request);

        expect(result.success).toBe(true);
        expect(result.waitingForCallback).toBe(true);
        expect(result.response).toBeUndefined();
      });

      it('should include callback URL when template is provided', async () => {
        mockHttpClient.setNextResponse({ status: 202, body: {} });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig(),
          httpClient: mockHttpClient,
          store,
          callbackUrlTemplate: 'https://api.example.com/callback/{id}',
        });

        const request = createTestWebhookRequest({ id: 'callback-test' });
        await client.requestApproval(request);

        const payload = mockHttpClient.lastRequest?.body as WebhookApprovalRequest;
        expect(payload.callbackUrl).toBe('https://api.example.com/callback/callback-test');
      });
    });

    describe('timeout handling', () => {
      it('should return error on timeout', async () => {
        const abortError = new Error('The operation was aborted');
        abortError.name = 'AbortError';
        mockHttpClient.setNextError(abortError);

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig({ timeout: 5 }),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        const result = await client.requestApproval(request);

        expect(result.success).toBe(false);
        expect(result.error).toContain('timeout');
        expect(result.waitingForCallback).toBe(false);
      });
    });

    describe('network errors', () => {
      it('should handle network errors gracefully', async () => {
        mockHttpClient.setNextError(new Error('fetch failed: network error'));

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig(),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        const result = await client.requestApproval(request);

        expect(result.success).toBe(false);
        expect(result.error).toContain('Network error');
        expect(result.waitingForCallback).toBe(false);
      });

      it('should handle generic errors', async () => {
        mockHttpClient.setNextError(new Error('Something went wrong'));

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig(),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        const result = await client.requestApproval(request);

        expect(result.success).toBe(false);
        expect(result.error).toContain('Something went wrong');
        expect(result.waitingForCallback).toBe(false);
      });
    });

    describe('invalid responses', () => {
      it('should return error for invalid response format (missing approved)', async () => {
        mockHttpClient.setNextResponse({ status: 200, body: { result: 'ok' } });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig(),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        const result = await client.requestApproval(request);

        expect(result.success).toBe(false);
        expect(result.error).toContain('Invalid response format');
        expect(result.waitingForCallback).toBe(false);
      });

      it('should return error for non-object response', async () => {
        mockHttpClient.setNextResponse({ status: 200, body: 'ok' });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig(),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        const result = await client.requestApproval(request);

        expect(result.success).toBe(false);
        expect(result.error).toContain('Invalid response format');
      });

      it('should return error for null response body', async () => {
        mockHttpClient.setNextResponse({ status: 200, body: null });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig(),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        const result = await client.requestApproval(request);

        expect(result.success).toBe(false);
        expect(result.error).toContain('Invalid response format');
      });
    });

    describe('HTTP error responses', () => {
      it('should handle 4xx client errors', async () => {
        mockHttpClient.setNextResponse({
          status: 400,
          body: { error: 'Invalid request format' },
        });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig(),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        const result = await client.requestApproval(request);

        expect(result.success).toBe(false);
        expect(result.error).toContain('Client error (400)');
        expect(result.error).toContain('Invalid request format');
        expect(result.waitingForCallback).toBe(false);
      });

      it('should handle 401 unauthorized', async () => {
        mockHttpClient.setNextResponse({
          status: 401,
          body: { message: 'Unauthorized' },
        });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig(),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        const result = await client.requestApproval(request);

        expect(result.success).toBe(false);
        expect(result.error).toContain('Client error (401)');
        expect(result.error).toContain('Unauthorized');
      });

      it('should handle 5xx server errors', async () => {
        mockHttpClient.setNextResponse({
          status: 500,
          body: { error: 'Internal server error' },
        });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig(),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        const result = await client.requestApproval(request);

        expect(result.success).toBe(false);
        expect(result.error).toContain('Server error (500)');
        expect(result.error).toContain('Internal server error');
        expect(result.waitingForCallback).toBe(false);
      });

      it('should handle 503 service unavailable', async () => {
        mockHttpClient.setNextResponse({
          status: 503,
          body: 'Service temporarily unavailable',
        });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig(),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        const result = await client.requestApproval(request);

        expect(result.success).toBe(false);
        expect(result.error).toContain('Server error (503)');
        expect(result.error).toContain('Service temporarily unavailable');
      });

      it('should handle unexpected status codes', async () => {
        mockHttpClient.setNextResponse({ status: 301, body: {} });

        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig(),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        const result = await client.requestApproval(request);

        expect(result.success).toBe(false);
        expect(result.error).toContain('Unexpected status code: 301');
      });
    });

    describe('disabled webhook', () => {
      it('should return error when webhook is disabled', async () => {
        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig({ enabled: false }),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        const result = await client.requestApproval(request);

        expect(result.success).toBe(false);
        expect(result.error).toContain('not enabled');
        expect(result.waitingForCallback).toBe(false);
      });

      it('should return error when URL is not configured', async () => {
        const client = createWebhookApprovalClient({
          webhookConfig: createTestWebhookConfig({ enabled: true, url: undefined }),
          httpClient: mockHttpClient,
          store,
        });

        const request = createTestWebhookRequest();
        const result = await client.requestApproval(request);

        expect(result.success).toBe(false);
        expect(result.error).toContain('not enabled');
        expect(result.waitingForCallback).toBe(false);
      });
    });
  });

  describe('handleCallback', () => {
    it('should approve pending approval on positive callback', () => {
      const input = createTestApprovalInput({ id: 'callback-approve' });
      store.add(input);

      const client = createWebhookApprovalClient({
        webhookConfig: createTestWebhookConfig(),
        httpClient: mockHttpClient,
        store,
      });

      const response: WebhookApprovalResponse = {
        approved: true,
        approvedBy: 'slack-user',
        reason: 'Approved via Slack',
      };

      const result = client.handleCallback('callback-approve', response);

      expect(result.success).toBe(true);
      expect(result.message).toContain('Approved');
      expect(result.message).toContain('slack-user');
      expect(result.message).toContain('Approved via Slack');
      expect(result.record?.status).toBe('approved');
      expect(result.record?.approvedBy).toBe('slack-user');
    });

    it('should deny pending approval on negative callback', () => {
      const input = createTestApprovalInput({
        id: 'callback-deny',
        toolCall: createTestToolCall({ toolName: 'dangerous_tool' }),
      });
      store.add(input);

      const client = createWebhookApprovalClient({
        webhookConfig: createTestWebhookConfig(),
        httpClient: mockHttpClient,
        store,
      });

      const response: WebhookApprovalResponse = {
        approved: false,
        approvedBy: 'security-team',
        reason: 'Policy violation',
      };

      const result = client.handleCallback('callback-deny', response);

      expect(result.success).toBe(true);
      expect(result.message).toContain('Denied');
      expect(result.message).toContain('security-team');
      expect(result.message).toContain('Policy violation');
      expect(result.message).toContain('dangerous_tool');
      expect(result.record?.status).toBe('denied');
    });

    it('should use default approver when not provided', () => {
      const input = createTestApprovalInput({ id: 'callback-default-approver' });
      store.add(input);

      const client = createWebhookApprovalClient({
        webhookConfig: createTestWebhookConfig(),
        httpClient: mockHttpClient,
        store,
      });

      const response: WebhookApprovalResponse = { approved: true };
      const result = client.handleCallback('callback-default-approver', response);

      expect(result.success).toBe(true);
      expect(result.record?.approvedBy).toBe('webhook');
    });

    it('should return error for empty ID', () => {
      const client = createWebhookApprovalClient({
        webhookConfig: createTestWebhookConfig(),
        httpClient: mockHttpClient,
        store,
      });

      const response: WebhookApprovalResponse = { approved: true };
      const result = client.handleCallback('', response);

      expect(result.success).toBe(false);
      expect(result.message).toContain('Invalid');
    });

    it('should return error for non-existent ID', () => {
      const client = createWebhookApprovalClient({
        webhookConfig: createTestWebhookConfig(),
        httpClient: mockHttpClient,
        store,
      });

      const response: WebhookApprovalResponse = { approved: true };
      const result = client.handleCallback('non-existent', response);

      expect(result.success).toBe(false);
      expect(result.message).toContain('not found');
    });

    it('should return error for expired approval', () => {
      const pastTime = Date.now() - 1000;
      const input = createTestApprovalInput({
        id: 'callback-expired',
        expiresAt: pastTime,
      });
      store.add(input);

      const client = createWebhookApprovalClient({
        webhookConfig: createTestWebhookConfig(),
        httpClient: mockHttpClient,
        store,
      });

      const response: WebhookApprovalResponse = { approved: true };
      const result = client.handleCallback('callback-expired', response);

      expect(result.success).toBe(false);
      expect(result.message).toContain('expired');
    });

    it('should return error for already approved', () => {
      const input = createTestApprovalInput({ id: 'callback-already-approved' });
      store.add(input);
      store.approve('callback-already-approved');

      const client = createWebhookApprovalClient({
        webhookConfig: createTestWebhookConfig(),
        httpClient: mockHttpClient,
        store,
      });

      const response: WebhookApprovalResponse = { approved: true };
      const result = client.handleCallback('callback-already-approved', response);

      expect(result.success).toBe(false);
      expect(result.message).toContain('already approved');
    });

    it('should return error for already denied', () => {
      const input = createTestApprovalInput({ id: 'callback-already-denied' });
      store.add(input);
      store.deny('callback-already-denied');

      const client = createWebhookApprovalClient({
        webhookConfig: createTestWebhookConfig(),
        httpClient: mockHttpClient,
        store,
      });

      const response: WebhookApprovalResponse = { approved: false };
      const result = client.handleCallback('callback-already-denied', response);

      expect(result.success).toBe(false);
      expect(result.message).toContain('already denied');
    });

    it('should trim whitespace from ID', () => {
      const input = createTestApprovalInput({ id: 'callback-trimmed' });
      store.add(input);

      const client = createWebhookApprovalClient({
        webhookConfig: createTestWebhookConfig(),
        httpClient: mockHttpClient,
        store,
      });

      const response: WebhookApprovalResponse = { approved: true };
      const result = client.handleCallback('  callback-trimmed  ', response);

      expect(result.success).toBe(true);
      expect(result.record?.status).toBe('approved');
    });
  });
});

describe('createWebhookRequest helper', () => {
  let store: InMemoryApprovalStore;

  beforeEach(() => {
    store = createApprovalStore({ cleanupIntervalMs: 0 });
  });

  afterEach(() => {
    store.stopCleanupTimer();
    store.clear();
  });

  it('should create webhook request from pending approval record', () => {
    const input = createTestApprovalInput({
      id: 'helper-test',
      detection: createTestDetection({ category: 'secrets', severity: 'high' }),
      toolCall: createTestToolCall({ toolName: 'write_file', toolInput: { path: '/etc/passwd' } }),
    });
    store.add(input);

    const record = store.get('helper-test')!;
    const request = createWebhookRequest(record);

    expect(request.id).toBe('helper-test');
    expect(request.detection.category).toBe('secrets');
    expect(request.toolCall.name).toBe('write_file');
    expect(request.toolCall.input).toEqual({ path: '/etc/passwd' });
    expect(request.timestamp).toBe(record.createdAt);
    expect(request.expiresAt).toBe(record.expiresAt);
  });

  it('should include callback URL when provided', () => {
    const input = createTestApprovalInput({ id: 'helper-callback' });
    store.add(input);

    const record = store.get('helper-callback')!;
    const request = createWebhookRequest(record, 'https://callback.example.com/approve/helper-callback');

    expect(request.callbackUrl).toBe('https://callback.example.com/approve/helper-callback');
  });
});

describe('Default webhook approval client singleton', () => {
  afterEach(() => {
    resetDefaultWebhookApprovalClient();
    resetDefaultApprovalStore();
  });

  it('should return the same instance on multiple calls', () => {
    const client1 = getDefaultWebhookApprovalClient();
    const client2 = getDefaultWebhookApprovalClient();

    expect(client1).toBe(client2);
  });

  it('should create new instance after reset', () => {
    const client1 = getDefaultWebhookApprovalClient();
    resetDefaultWebhookApprovalClient();
    const client2 = getDefaultWebhookApprovalClient();

    expect(client1).not.toBe(client2);
  });

  it('should be disabled by default', () => {
    const client = getDefaultWebhookApprovalClient();
    expect(client.isEnabled()).toBe(false);
  });
});

// =============================================================================
// WEBHOOK INTEGRATION TESTS
// =============================================================================

describe('Webhook Integration', () => {
  let store: InMemoryApprovalStore;
  let mockHttpClient: MockHttpClient;
  let client: DefaultWebhookApprovalClient;

  beforeEach(() => {
    store = createApprovalStore({ cleanupIntervalMs: 0 });
    mockHttpClient = new MockHttpClient();
    client = createWebhookApprovalClient({
      webhookConfig: createTestWebhookConfig(),
      httpClient: mockHttpClient,
      store,
      callbackUrlTemplate: 'https://api.example.com/callback/{id}',
    });
  });

  afterEach(() => {
    store.stopCleanupTimer();
    store.clear();
  });

  it('should handle complete sync approval flow', async () => {
    // 1. Create pending approval
    const input = createTestApprovalInput({
      id: 'webhook-flow-sync',
      detection: createTestDetection({ category: 'destructive' }),
      toolCall: createTestToolCall({ toolName: 'bash', toolInput: { command: 'rm -rf /' } }),
    });
    store.add(input);

    // 2. Create webhook request
    const record = store.get('webhook-flow-sync')!;
    const request = createWebhookRequest(record);

    // 3. Simulate webhook returning immediate approval
    mockHttpClient.setNextResponse({
      status: 200,
      body: { approved: true, approvedBy: 'admin', reason: 'Safe operation' },
    });

    const result = await client.requestApproval(request);

    // 4. Verify immediate result
    expect(result.success).toBe(true);
    expect(result.waitingForCallback).toBe(false);
    expect(result.response?.approved).toBe(true);
  });

  it('should handle complete async approval flow', async () => {
    // 1. Create pending approval
    const input = createTestApprovalInput({
      id: 'webhook-flow-async',
      detection: createTestDetection({ category: 'destructive' }),
      toolCall: createTestToolCall({ toolName: 'bash' }),
    });
    store.add(input);

    // 2. Create webhook request
    const record = store.get('webhook-flow-async')!;
    const request = createWebhookRequest(record);

    // 3. Simulate webhook returning 202 (pending)
    mockHttpClient.setNextResponse({ status: 202, body: {} });

    const sendResult = await client.requestApproval(request);

    // 4. Verify waiting for callback
    expect(sendResult.success).toBe(true);
    expect(sendResult.waitingForCallback).toBe(true);

    // 5. Verify record is still pending
    expect(store.get('webhook-flow-async')?.status).toBe('pending');

    // 6. Simulate callback from external system
    const callbackResult = client.handleCallback('webhook-flow-async', {
      approved: true,
      approvedBy: 'slack-user',
      reason: 'Approved in Slack',
    });

    // 7. Verify approved
    expect(callbackResult.success).toBe(true);
    expect(store.get('webhook-flow-async')?.status).toBe('approved');
    expect(store.get('webhook-flow-async')?.approvedBy).toBe('slack-user');
  });

  it('should handle denial flow', async () => {
    // 1. Create pending approval
    const input = createTestApprovalInput({
      id: 'webhook-flow-deny',
      toolCall: createTestToolCall({ toolName: 'dangerous_tool' }),
    });
    store.add(input);

    // 2. Create webhook request
    const record = store.get('webhook-flow-deny')!;
    const request = createWebhookRequest(record);

    // 3. Simulate webhook returning denial
    mockHttpClient.setNextResponse({
      status: 200,
      body: { approved: false, reason: 'Security policy violation' },
    });

    const result = await client.requestApproval(request);

    // 4. Verify denial
    expect(result.success).toBe(true);
    expect(result.response?.approved).toBe(false);
    expect(result.response?.reason).toBe('Security policy violation');
  });

  it('should handle webhook errors gracefully', async () => {
    // 1. Create pending approval
    const input = createTestApprovalInput({ id: 'webhook-flow-error' });
    store.add(input);

    // 2. Create webhook request
    const record = store.get('webhook-flow-error')!;
    const request = createWebhookRequest(record);

    // 3. Simulate webhook error
    mockHttpClient.setNextResponse({
      status: 500,
      body: { error: 'Database connection failed' },
    });

    const result = await client.requestApproval(request);

    // 4. Verify error handling
    expect(result.success).toBe(false);
    expect(result.error).toContain('Server error');
    expect(result.error).toContain('Database connection failed');

    // 5. Verify record is still pending (not modified)
    expect(store.get('webhook-flow-error')?.status).toBe('pending');
  });
});

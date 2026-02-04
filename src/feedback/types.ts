/**
 * Feedback Types
 * Type definitions for user feedback on detection accuracy
 */

import type { ThreatCategory } from '../engine/index.js';
import type { Severity } from '../config/index.js';

/**
 * Status of a feedback entry
 */
export type FeedbackStatus = 'pending' | 'reviewed' | 'applied';

/**
 * Type of feedback
 */
export type FeedbackType = 'false-positive' | 'false-negative';

/**
 * Detection context stored with false positive feedback
 */
export interface FeedbackDetectionContext {
  /** Category of threat that was detected */
  category: ThreatCategory;
  /** Severity level of the detection */
  severity: Severity;
  /** Reason given for the detection */
  reason: string;
  /** Name of the tool that was blocked */
  toolName: string;
  /** Input parameters that triggered the detection */
  toolInput: Record<string, unknown>;
}

/**
 * A feedback entry from a user
 */
export interface FeedbackEntry {
  /** Unique identifier for this feedback */
  id: string;
  /** Type of feedback */
  type: FeedbackType;
  /** Unix timestamp when feedback was submitted */
  timestamp: number;
  /** Detection ID for false positives (links to audit log) */
  detectionId?: string;
  /** Full detection context for false positives */
  detection?: FeedbackDetectionContext;
  /** User description for false negatives */
  description?: string;
  /** Suggested category for false negatives */
  suggestedCategory?: ThreatCategory;
  /** Current status of the feedback */
  status: FeedbackStatus;
  /** Optional notes (e.g., from review process) */
  notes?: string;
}

/**
 * Options for creating a false positive feedback entry
 */
export interface FalsePositiveOptions {
  /** Detection ID from audit log */
  detectionId: string;
  /** Full detection context */
  detection?: FeedbackDetectionContext;
}

/**
 * Options for creating a false negative feedback entry
 */
export interface FalseNegativeOptions {
  /** Description of what was missed */
  description: string;
  /** Suggested category for the missed threat */
  suggestedCategory?: ThreatCategory;
}

/**
 * Input for creating a new feedback entry (without auto-generated fields)
 */
export type FeedbackInput = Omit<FeedbackEntry, 'id' | 'timestamp' | 'status'>;

/**
 * Interface for feedback storage operations
 */
export interface FeedbackStore {
  /** Add a new feedback entry */
  add(entry: FeedbackInput): FeedbackEntry;
  /** Get a feedback entry by ID */
  get(id: string): FeedbackEntry | undefined;
  /** Get all feedback entries */
  getAll(): FeedbackEntry[];
  /** Get feedback entries by type */
  getByType(type: FeedbackType): FeedbackEntry[];
  /** Update the status of a feedback entry */
  updateStatus(id: string, status: FeedbackStatus, notes?: string): boolean;
  /** Remove a feedback entry */
  remove(id: string): boolean;
  /** Save feedback to persistent storage */
  save(): Promise<void>;
  /** Load feedback from persistent storage */
  load(): Promise<void>;
}

/**
 * Options for the feedback CLI command
 */
export interface FeedbackOptions {
  /** Report a false positive by detection ID */
  falsePositive?: string;
  /** Report a false negative with description */
  falseNegative?: string;
  /** Suggested category for false negative */
  category?: ThreatCategory;
  /** List all feedback entries */
  list?: boolean;
  /** Filter list by type */
  type?: FeedbackType;
  /** Show details of a specific feedback entry */
  show?: string;
}

/**
 * Result of the feedback command
 */
export interface FeedbackResult {
  /** Whether the operation was successful */
  success: boolean;
  /** Message to display to the user */
  message: string;
  /** Feedback entries (for list/show operations) */
  entries?: FeedbackEntry[];
  /** Single entry (for add/show operations) */
  entry?: FeedbackEntry;
}

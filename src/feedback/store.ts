/**
 * Feedback Store
 * File-based storage for user feedback on detection accuracy
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type {
  FeedbackEntry,
  FeedbackInput,
  FeedbackStatus,
  FeedbackStore,
  FeedbackType,
} from './types.js';

/** Default storage directory relative to project root */
const DEFAULT_STORAGE_DIR = '.clawsec';

/** Default storage filename */
const DEFAULT_STORAGE_FILE = 'feedback.json';

/** Debounce delay for auto-save in milliseconds */
const SAVE_DEBOUNCE_MS = 1000;

/**
 * File-based feedback storage implementation
 */
export class FileFeedbackStore implements FeedbackStore {
  private entries: Map<string, FeedbackEntry> = new Map();
  private filePath: string;
  private saveTimeout: ReturnType<typeof setTimeout> | null = null;
  private loaded = false;

  /**
   * Create a new file-based feedback store
   * 
   * @param projectRoot - Root directory of the project (default: current working directory)
   * @param filename - Name of the storage file (default: feedback.json)
   */
  constructor(projectRoot?: string, filename?: string) {
    const root = projectRoot ?? process.cwd();
    const file = filename ?? DEFAULT_STORAGE_FILE;
    this.filePath = join(root, DEFAULT_STORAGE_DIR, file);
  }

  /**
   * Add a new feedback entry
   * 
   * @param input - Feedback entry data (without id, timestamp, status)
   * @returns The created feedback entry with generated fields
   */
  add(input: FeedbackInput): FeedbackEntry {
    const entry: FeedbackEntry = {
      ...input,
      id: randomUUID(),
      timestamp: Date.now(),
      status: 'pending',
    };

    this.entries.set(entry.id, entry);
    this.scheduleSave();

    return entry;
  }

  /**
   * Get a feedback entry by ID
   * 
   * @param id - The feedback entry ID
   * @returns The feedback entry or undefined if not found
   */
  get(id: string): FeedbackEntry | undefined {
    return this.entries.get(id);
  }

  /**
   * Get all feedback entries
   * 
   * @returns Array of all feedback entries sorted by timestamp (newest first)
   */
  getAll(): FeedbackEntry[] {
    return Array.from(this.entries.values())
      .sort((a, b) => b.timestamp - a.timestamp);
  }

  /**
   * Get feedback entries filtered by type
   * 
   * @param type - The feedback type to filter by
   * @returns Array of matching feedback entries sorted by timestamp (newest first)
   */
  getByType(type: FeedbackType): FeedbackEntry[] {
    return this.getAll().filter(entry => entry.type === type);
  }

  /**
   * Update the status of a feedback entry
   * 
   * @param id - The feedback entry ID
   * @param status - The new status
   * @param notes - Optional notes to add
   * @returns True if the entry was updated, false if not found
   */
  updateStatus(id: string, status: FeedbackStatus, notes?: string): boolean {
    const entry = this.entries.get(id);
    if (!entry) {
      return false;
    }

    entry.status = status;
    if (notes !== undefined) {
      entry.notes = notes;
    }

    this.scheduleSave();
    return true;
  }

  /**
   * Remove a feedback entry
   * 
   * @param id - The feedback entry ID
   * @returns True if the entry was removed, false if not found
   */
  remove(id: string): boolean {
    const result = this.entries.delete(id);
    if (result) {
      this.scheduleSave();
    }
    return result;
  }

  /**
   * Save feedback entries to the storage file
   */
  async save(): Promise<void> {
    // Cancel any pending debounced save
    if (this.saveTimeout) {
      clearTimeout(this.saveTimeout);
      this.saveTimeout = null;
    }

    // Ensure directory exists
    await mkdir(dirname(this.filePath), { recursive: true });

    // Convert entries to array for JSON serialization
    const data = Array.from(this.entries.values());
    const json = JSON.stringify(data, null, 2);

    await writeFile(this.filePath, json, 'utf-8');
  }

  /**
   * Load feedback entries from the storage file
   */
  async load(): Promise<void> {
    try {
      const json = await readFile(this.filePath, 'utf-8');
      const data = JSON.parse(json) as FeedbackEntry[];

      this.entries.clear();
      for (const entry of data) {
        this.entries.set(entry.id, entry);
      }
      this.loaded = true;
    } catch (error) {
      // File doesn't exist or is invalid - start with empty store
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        // Log non-ENOENT errors for debugging
        console.warn(`Warning: Could not load feedback store: ${(error as Error).message}`);
      }
      this.entries.clear();
      this.loaded = true;
    }
  }

  /**
   * Check if the store has been loaded from disk
   */
  isLoaded(): boolean {
    return this.loaded;
  }

  /**
   * Get the number of entries in the store
   */
  size(): number {
    return this.entries.size;
  }

  /**
   * Clear all entries from the store
   * Note: Does not automatically save - call save() explicitly if needed
   */
  clear(): void {
    this.entries.clear();
    if (this.saveTimeout) {
      clearTimeout(this.saveTimeout);
      this.saveTimeout = null;
    }
  }

  /**
   * Get the storage file path
   */
  getFilePath(): string {
    return this.filePath;
  }

  /**
   * Schedule a debounced save operation
   */
  private scheduleSave(): void {
    if (this.saveTimeout) {
      clearTimeout(this.saveTimeout);
    }

    this.saveTimeout = setTimeout(() => {
      this.save().catch(error => {
        console.error(`Failed to save feedback store: ${(error as Error).message}`);
      });
    }, SAVE_DEBOUNCE_MS);
  }
}

/**
 * Global feedback store instance
 * Lazily initialized on first access
 */
let globalStore: FileFeedbackStore | null = null;

/**
 * Get the global feedback store instance
 * 
 * @param projectRoot - Optional project root to use for storage location
 * @returns The global feedback store instance
 */
export function getFeedbackStore(projectRoot?: string): FileFeedbackStore {
  if (!globalStore) {
    globalStore = new FileFeedbackStore(projectRoot);
  }
  return globalStore;
}

/**
 * Reset the global feedback store (primarily for testing)
 */
export function resetGlobalFeedbackStore(): void {
  if (globalStore) {
    globalStore.clear();
  }
  globalStore = null;
}

/**
 * Create a new feedback store with a specific storage location
 * 
 * @param projectRoot - Project root directory
 * @param filename - Optional custom filename
 * @returns A new FileFeedbackStore instance
 */
export function createFeedbackStore(projectRoot: string, filename?: string): FileFeedbackStore {
  return new FileFeedbackStore(projectRoot, filename);
}

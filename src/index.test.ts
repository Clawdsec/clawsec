import { describe, it, expect } from 'vitest';
import { VERSION } from './index.js';

describe('Clawsec', () => {
  it('exports version', () => {
    expect(VERSION).toBe('1.0.0');
  });
});

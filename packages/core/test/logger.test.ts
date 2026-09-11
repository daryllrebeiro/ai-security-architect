import { describe, it, expect } from 'vitest';
import {
  StructuredLogger,
  createLogger,
  createContextLogger,
  type LogEntry,
} from '../src/index.js';

describe('Milestone 1.3: Contextual Structured Logger', () => {
  it('emits structured JSON entries with correlation ID and default context', () => {
    const entries: LogEntry[] = [];
    const logger = new StructuredLogger({
      correlationId: 'corr-xyz-123',
      defaultContext: { service: 'security-engine' },
      sink: (entry) => entries.push(entry),
      minLevel: 'debug',
    });

    logger.info('Scan initiated', { target: 'repo-abc' });

    expect(entries).toHaveLength(1);
    expect(entries[0].correlationId).toBe('corr-xyz-123');
    expect(entries[0].level).toBe('info');
    expect(entries[0].message).toBe('Scan initiated');
    expect(entries[0].context).toEqual({
      service: 'security-engine',
      target: 'repo-abc',
    });
    expect(entries[0].timestamp).toBeDefined();
  });

  it('respects log level thresholds', () => {
    const entries: LogEntry[] = [];
    const logger = createLogger({
      minLevel: 'warn',
      sink: (entry) => entries.push(entry),
    });

    logger.debug('Debug msg');
    logger.info('Info msg');
    logger.warn('Warning alert');
    logger.error('Error occurred');

    expect(entries).toHaveLength(2);
    expect(entries[0].level).toBe('warn');
    expect(entries[1].level).toBe('error');
  });

  it('captures error objects and stack traces on error logs', () => {
    const entries: LogEntry[] = [];
    const logger = createLogger({
      sink: (entry) => entries.push(entry),
      minLevel: 'info',
    });

    const err = new Error('Database connection failed');
    logger.error('Operation failed', err, { retryCount: 3 });

    expect(entries).toHaveLength(1);
    expect(entries[0].error?.message).toBe('Database connection failed');
    expect(entries[0].error?.name).toBe('Error');
    expect(entries[0].error?.stack).toBeDefined();
    expect(entries[0].context?.retryCount).toBe(3);
  });

  it('creates child loggers with merged context', () => {
    const entries: LogEntry[] = [];
    const parent = createContextLogger('corr-parent-1', { component: 'scanner' });
    (parent as any).sink = (entry: LogEntry) => entries.push(entry);

    const child = parent.child({ subtask: 'ast-parser' });
    child.info('Parsing complete');

    expect(entries).toHaveLength(1);
    expect(entries[0].correlationId).toBe('corr-parent-1');
    expect(entries[0].context).toEqual({
      component: 'scanner',
      subtask: 'ast-parser',
    });
  });
});

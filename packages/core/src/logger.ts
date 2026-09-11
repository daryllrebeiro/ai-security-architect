import { randomUUID } from 'crypto';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  correlationId?: string;
  context?: Record<string, unknown>;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
}

export type LogSink = (entry: LogEntry) => void;

export interface LoggerOptions {
  correlationId?: string;
  defaultContext?: Record<string, unknown>;
  minLevel?: LogLevel;
  sink?: LogSink;
}

const LOG_LEVEL_SEVERITY: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export class StructuredLogger {
  private readonly correlationId: string;
  private readonly defaultContext: Record<string, unknown>;
  private readonly minLevel: LogLevel;
  private readonly sink: LogSink;

  constructor(options: LoggerOptions = {}) {
    this.correlationId = options.correlationId ?? randomUUID();
    this.defaultContext = { ...(options.defaultContext || {}) };
    this.minLevel = options.minLevel ?? (process.env.LOG_LEVEL as LogLevel) ?? 'info';
    this.sink =
      options.sink ??
      ((entry) => {
        const out = JSON.stringify(entry);
        if (entry.level === 'error') {
          process.stderr.write(out + '\n');
        } else {
          process.stdout.write(out + '\n');
        }
      });
  }

  public getCorrelationId(): string {
    return this.correlationId;
  }

  private shouldLog(level: LogLevel): boolean {
    return LOG_LEVEL_SEVERITY[level] >= LOG_LEVEL_SEVERITY[this.minLevel];
  }

  private emit(level: LogLevel, message: string, context?: Record<string, unknown>, err?: unknown): void {
    if (!this.shouldLog(level)) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      correlationId: this.correlationId,
      context: { ...this.defaultContext, ...(context || {}) },
    };

    if (err) {
      if (err instanceof Error) {
        entry.error = {
          name: err.name,
          message: err.message,
          stack: err.stack,
        };
      } else {
        entry.error = {
          name: 'Error',
          message: String(err),
        };
      }
    }

    this.sink(entry);
  }

  public debug(message: string, context?: Record<string, unknown>): void {
    this.emit('debug', message, context);
  }

  public info(message: string, context?: Record<string, unknown>): void {
    this.emit('info', message, context);
  }

  public warn(message: string, context?: Record<string, unknown>): void {
    this.emit('warn', message, context);
  }

  public error(message: string, errOrContext?: unknown, context?: Record<string, unknown>): void {
    if (errOrContext instanceof Error) {
      this.emit('error', message, context, errOrContext);
    } else if (typeof errOrContext === 'object' && errOrContext !== null && !context) {
      this.emit('error', message, errOrContext as Record<string, unknown>);
    } else {
      this.emit('error', message, context, errOrContext);
    }
  }

  public child(additionalContext: Record<string, unknown>): StructuredLogger {
    return new StructuredLogger({
      correlationId: this.correlationId,
      defaultContext: { ...this.defaultContext, ...additionalContext },
      minLevel: this.minLevel,
      sink: this.sink,
    });
  }

  public withCorrelationId(correlationId: string): StructuredLogger {
    return new StructuredLogger({
      correlationId,
      defaultContext: { ...this.defaultContext },
      minLevel: this.minLevel,
      sink: this.sink,
    });
  }
}

export function createLogger(options?: LoggerOptions): StructuredLogger {
  return new StructuredLogger(options);
}

export function createContextLogger(correlationId: string, defaultContext?: Record<string, unknown>): StructuredLogger {
  return new StructuredLogger({ correlationId, defaultContext });
}

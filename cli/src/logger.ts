export type Level = 'CRITICAL' | 'ERROR' | 'WARNING' | 'INFO' | 'DEBUG' | 'SILLY';
export const Levels: Level[] = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'SILLY'];

export class CLIError extends Error {
  prefix: Level;
  cause?: Error;
  constructor(prefix: Level, message: string, cause?: Error) {
    super();
    this.prefix = prefix;
    this.message = message;
    this.cause = cause;
  }
}

export type Logger = {
  (e: Error | CLIError | Level, message?: string): void;
  level: Level;
};

export const log: Logger = Object.assign(
  (thing: Error | CLIError | Level, message?: string) => {
    let e: Error | null;
    let m: string;
    let l: Level;

    if (thing instanceof CLIError) {
      l = thing.prefix;
      m = thing.message;
      e = thing as Error;
    } else if (thing instanceof Error) {
      l = 'CRITICAL';
      m = thing.message;
      e = thing as Error;
    } else {
      l = thing as Level;
      m = message || '';
      e = null;
    }
    const prefixed = `[${l}] ${m}`;
    const i = Levels.indexOf(l);
    if (i <= Levels.indexOf(log.level)) {
      switch (l) {
        case 'CRITICAL':
        case 'ERROR':
          if (e && !(e instanceof CLIError)) {
            console.error(prefixed, e);
          } else {
            console.error(prefixed);
          }
          break;
        case 'WARNING':
          if (e) {
            console.warn(prefixed, e);
          } else {
            console.warn(prefixed);
          }
          break;
        case 'INFO':
          console.info(prefixed);
          break;
        default:
          console.log(prefixed);
          break;
      }
    }
    if (log.level === 'SILLY') {
      console.error(e);
    }
    if (l === 'CRITICAL') {
      process.exit(1);
    }
  },
  { level: 'INFO' as Level }
);

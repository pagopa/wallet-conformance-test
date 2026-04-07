import { ConsolaInstance } from "consola";

export type Logger = Omit<
  ConsolaInstance,
  "create" | "withDefaults" | "withTag"
> & {
  flowStep: (
    index: number,
    total: number,
    name: string,
    success: boolean,
    durationMs: number,
  ) => void;
  nl: () => void;
  setLogOptions: SetLogOptionsCallback;
  testCompleted: (
    description: string,
    success: boolean,
    durationMs?: number,
  ) => void;
  testFailed: () => void;
  testSuite: (options: {
    profile: string;
    specsVersion: string;
    target: string;
    title: string;
  }) => void;
  testSummary: (
    suites: {
      durationMs: number;
      failed: number;
      name: string;
      passed: number;
    }[],
  ) => void;
  withTag: (tag: string) => Logger;
};

export interface SetLogOptions {
  fileFormat?: string;
  format?: string;
  level?: string;
  path?: string;
}

export type SetLogOptionsCallback = (options: SetLogOptions) => void;

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
    target: string;
    title: string;
  }) => void;
  withTag: (tag: string) => Logger;
};

export type SetLogOptionsCallback = (options: {
  format?: string;
  level?: string;
  path?: string;
}) => void;

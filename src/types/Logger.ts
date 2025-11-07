import { ConsolaInstance } from "consola";

export type Logger = Omit<
  ConsolaInstance,
  "create" | "withDefaults" | "withTag"
> & {
  nl: () => void;
  setLogOptions: SetLogOptionsCallback;
  testCompleted: () => void;
  testFailed: () => void;
  withTag: (tag: string) => Logger;
};

export type SetLogOptionsCallback = (options: {
  format?: string;
  level?: string;
  path?: string;
}) => void;

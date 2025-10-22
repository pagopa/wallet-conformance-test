import { ConsolaInstance } from "consola";

export type Logger = ConsolaInstance & {
  setLogOptions: SetLogOptionsCallback;
};

export type SetLogOptionsCallback = (
  this: ConsolaInstance,
  options: {
    format?: string;
    level?: string;
    path?: string;
  },
) => void;

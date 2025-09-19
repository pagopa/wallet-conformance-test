import { ConsolaInstance } from "consola"

export type SetLogOptionsCallback = (
	this: ConsolaInstance,
	options: {
		level?: string,
		format?: string,
		path?: string
	}
) => void;

export type Logger = ConsolaInstance & {
	setLogOptions: SetLogOptionsCallback
}
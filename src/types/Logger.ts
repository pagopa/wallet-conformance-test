import { Logger } from "ts-log";

export class Log implements Logger {
	trace(message?: any, ...optionalParams: any[]) {
		const output = optionalParams.length > 0 
			? `${message} ${JSON.stringify(optionalParams, null, 4)}`
			: message
		console.trace("TRACE:", output);
	}
	debug(message?: any, ...optionalParams: any[]) {
		const output = optionalParams.length > 0 
			? `${message} ${JSON.stringify(optionalParams, null, 4)}`
			: message
		console.debug("DEBUG:", output);
	}
	info(message?: any, ...optionalParams: any[]) {
		const output = optionalParams.length > 0 
			? `${message} ${JSON.stringify(optionalParams, null, 4)}`
			: message
		console.info("INFO:", output);
	}
	warn(message?: any, ...optionalParams: any[]) {
		const output = optionalParams.length > 0 
			? `${message} ${JSON.stringify(optionalParams, null, 4)}`
			: message
		console.warn("WARN:", output);
	}
	error(message?: any, ...optionalParams: any[]) {
		const output = optionalParams.length > 0 
			? `${message} ${JSON.stringify(optionalParams, null, 4)}`
			: message
		console.error("ERROR:", output);
	}
}
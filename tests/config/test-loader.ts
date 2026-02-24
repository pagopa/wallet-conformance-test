/**
 * Test Loader - Auto-discovery System
 *
 * Automatically loads test specifications, custom step classes, and step options
 * from configured directories using convention-over-configuration approach.
 *
 * Key features:
 * - Auto-discovery based on extends (prototype chain inspection)
 * - No manual registration required
 * - Supports both centralized (step-options.ts) and inline options
 * - Type-safe detection of step classes
 */

import { glob } from "glob";
import path from "path";
import { pathToFileURL } from "url";

import { loadConfigWithHierarchy } from "@/logic/config-loader";
import { createLogger } from "@/logic/logs";
import { FetchMetadataDefaultStep } from "@/step";
import {
  AuthorizeDefaultStep,
  CredentialRequestDefaultStep,
  NonceRequestDefaultStep,
  PushedAuthorizationRequestDefaultStep,
  TokenRequestDefaultStep,
} from "@/step/issuance";
import { AuthorizationRequestDefaultStep } from "@/step/presentation/authorization-request-step";
import { RedirectUriDefaultStep } from "@/step/presentation/redirect-uri-step";
import { StepFlow } from "@/step/step-flow";
import { Config } from "@/types";

export type CustomStepsMap = Record<string, StepClass>;

/**
 * Type for step class constructors
 * All step classes must extend StepFlow and accept config and logger
 */
export type StepClass = new (
  config: Config,
  logger: ReturnType<typeof createLogger>,
) => StepFlow;

/**
 * Base step classes for inheritance checking
 */
const ISSUANCE_STEP_CLASSES = {
  AuthorizeDefaultStep,
  CredentialRequestDefaultStep,
  FetchMetadataDefaultStep,
  NonceRequestDefaultStep,
  PushedAuthorizationRequestDefaultStep,
  TokenRequestDefaultStep,
} as const;

const PRESENTATION_STEP_CLASSES = {
  AuthorizationRequestDefaultStep,
  RedirectUriDefaultStep,
} as const;

/**
 * Mapping from step class name to step configuration key
 *
 * IMPORTANT: AuthorizationRequestDefaultStep mapping
 * - Internal key: "authorizationRequest" (used in discovery and step options)
 * - Config key: "authorize" (used in PresentationTestConfiguration)
 *
 * The mapping from "authorizationRequest" -> "authorize" happens in test-metadata.ts
 * when building PresentationTestConfiguration. This is because the presentation flow
 * uses "authorize" as the public-facing configuration key, while maintaining
 * consistency with the step class naming (AuthorizationRequestDefaultStep).
 *
 * Example:
 * - Step class: AuthorizationRequestDefaultStep
 * - Discovery key: "authorizationRequest" (via STEP_CLASS_TO_KEY)
 * - Final config key: "authorize" (remapped in definePresentationTest())
 */
const STEP_CLASS_TO_KEY: Record<string, string> = {
  AuthorizationRequestDefaultStep: "authorizationRequest", // Internal key
  AuthorizeDefaultStep: "authorize",
  CredentialRequestDefaultStep: "credentialRequest",
  FetchMetadataDefaultStep: "fetchMetadata",
  NonceRequestDefaultStep: "nonceRequest",
  PushedAuthorizationRequestDefaultStep: "pushedAuthorizationRequest",
  RedirectUriDefaultStep: "redirectUri",
  TokenRequestDefaultStep: "tokenRequest",
};

/**
 * TestLoader - Automatically discovers and loads test configurations
 *
 * Scans configured directories for:
 * 1. Test spec files (*.spec.ts) with metadata
 * 2. Custom step classes (extends base classes)
 * 3. Step options (step-options.ts or inline exports)
 */
export class TestLoader {
  private config = loadConfigWithHierarchy();
  private log = createLogger().withTag("TestLoader");

  /**
   * Auto-discovers custom step classes in directory
   * Uses prototype chain inspection to determine step type
   * @internal - Used by test-metadata helpers
   */
  async discoverCustomSteps(directory: string): Promise<CustomStepsMap> {
    const customSteps: CustomStepsMap = {};
    const customStepPattern = this.config.testing.custom_step_pattern;

    // Normalize path for glob (use forward slashes on all platforms)
    // glob expects forward slashes even on Windows
    const normalizedDirectory = directory.replace(/\\/g, "/");
    const searchPattern = `${normalizedDirectory}/${customStepPattern}`;
    this.log.debug(`Searching for custom steps in: ${searchPattern}`);

    const tsFiles = await glob(searchPattern, {
      ignore: ["**/*.spec.ts", "**/step-options.ts"],
    });

    this.log.debug(`Found ${tsFiles.length} TypeScript files to scan`);
    if (tsFiles.length > 0) {
      this.log.debug(`Files found: ${tsFiles.join(", ")}`);
    }

    for (const tsFile of tsFiles) {
      try {
        // Convert file path to URL for cross-platform import compatibility (Windows backslash support)
        const resolvedPath = path.resolve(tsFile);
        const fileUrl = pathToFileURL(resolvedPath).href;
        // Add timestamp to force fresh import (bypass cache)
        const urlWithTimestamp = `${fileUrl}?t=${Date.now()}`;

        this.log.debug(`Attempting to import: ${tsFile}`);
        this.log.debug(`  Resolved path: ${resolvedPath}`);
        this.log.debug(`  File URL: ${urlWithTimestamp}`);

        const module = await import(urlWithTimestamp);
        const fileName = path.basename(tsFile);

        // Check all exports for step classes
        const exportNames = Object.keys(module);
        this.log.debug(`  Module loaded, exports: ${exportNames.join(", ")}`);

        for (const [exportName, exportValue] of Object.entries(module)) {
          if (this.isStepClass(exportValue)) {
            const stepType = this.inferStepTypeFromExtends(exportValue);
            if (stepType) {
              customSteps[stepType] = exportValue;
              this.log.debug(
                `Auto-detected custom step: ${exportName} (${fileName}) -> ${stepType}`,
              );
            } else {
              this.log.warn(
                `Warning: ${exportName} in ${fileName} has run() method but doesn't extend any known step base class`,
              );
            }
          }
        }
      } catch (error) {
        // Log the error with full details for debugging
        const isNodeModules = tsFile.includes("node_modules");

        if (!isNodeModules) {
          this.log.error(
            `Failed to import ${path.basename(tsFile)}:`,
            error instanceof Error ? error.message : String(error),
          );
          if (error instanceof Error && error.stack) {
            this.log.error(`  Stack: ${error.stack}`);
          }
        }
      }
    }

    return customSteps;
  }
  /**
   * Checks if a class extends a specific base class
   * Uses prototype chain inspection
   * @param childClass The class to check
   * @param baseClass The base class to check against
   * @returns true if childClass extends baseClass
   */
  private extendsClass(childClass: unknown, baseClass: unknown): boolean {
    try {
      // Type guard to ensure both are constructor functions
      if (
        !childClass ||
        typeof childClass !== "function" ||
        !baseClass ||
        typeof baseClass !== "function"
      ) {
        return false;
      }

      // Cast to constructors for prototype access
      const childConstructor = childClass as new (
        ...args: unknown[]
      ) => unknown;
      const baseConstructor = baseClass as new (...args: unknown[]) => unknown;
      let proto = childConstructor.prototype;

      // Walk up the prototype chain
      while (proto) {
        // Direct comparison with base class prototype
        if (proto === baseConstructor.prototype) {
          return true;
        }

        // Also check constructor reference
        if (proto.constructor === baseConstructor) {
          return true;
        }

        proto = Object.getPrototypeOf(proto);
      }

      return false;
    } catch (error) {
      this.log.warn(
        `Error checking inheritance for ${(childClass as { name?: string })?.name}:`,
        error,
      );
      return false;
    }
  }

  /**
   * Infers step type from prototype chain (extends detection)
   * This is type-safe and robust - doesn't rely on naming conventions
   */
  private inferStepTypeFromExtends(stepClass: unknown): null | string {
    // Check against all known base classes
    const allBaseClasses = {
      ...ISSUANCE_STEP_CLASSES,
      ...PRESENTATION_STEP_CLASSES,
    };

    for (const [baseClassName, baseClass] of Object.entries(allBaseClasses)) {
      if (this.extendsClass(stepClass, baseClass)) {
        return STEP_CLASS_TO_KEY[baseClassName] || null;
      }
    }

    return null;
  }

  /**
   * Checks if an export is a step class (has a run method)
   */
  private isStepClass(value: unknown): value is StepClass {
    return (
      typeof value === "function" &&
      value.prototype &&
      typeof value.prototype.run === "function"
    );
  }
}

// Export singleton instance
export const testLoader = new TestLoader();

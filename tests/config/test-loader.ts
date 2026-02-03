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

type CustomStepsMap = Record<string, StepClass>;
/**
 * Type for step class constructors
 */
type StepClass = new (...args: any[]) => {
  run: (...args: any[]) => Promise<any>;
};
type StepOptionsMap = Record<string, Record<string, unknown>>;

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

    // Find all .ts files (excluding .spec.ts and step-options.ts)
    const tsFiles = await glob(path.join(directory, customStepPattern), {
      ignore: ["**/*.spec.ts", "**/step-options.ts"],
    });

    for (const tsFile of tsFiles) {
      try {
        const module = await import(tsFile);
        const fileName = path.basename(tsFile);

        // Check all exports for step classes
        for (const [exportName, exportValue] of Object.entries(module)) {
          if (this.isStepClass(exportValue)) {
            const stepType = this.inferStepTypeFromExtends(exportValue);
            if (stepType) {
              customSteps[stepType] = exportValue;
              this.log.info(
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
        // Log only if it's not a common ignorable error and not from node_modules
        const isModuleNotFound =
          error instanceof Error &&
          "code" in error &&
          error.code === "MODULE_NOT_FOUND";
        const isNodeModules = tsFile.includes("node_modules");

        if (!isModuleNotFound && !isNodeModules) {
          this.log.warn(
            `Failed to import ${path.basename(tsFile)}: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      }
    }

    return customSteps;
  }

  /**
   * Auto-discovers step options from step-options.ts or inline exports
   * Inline options have precedence over centralized options
   * @internal - Used by test-metadata helpers
   */
  async discoverStepOptions(
    directory: string,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _customSteps: CustomStepsMap,
  ): Promise<StepOptionsMap> {
    const stepOptions: StepOptionsMap = {};

    // 1. Load centralized step-options.ts if present
    const stepOptionsPath = path.join(directory, "step-options.ts");
    try {
      const optionsModule = await import(stepOptionsPath);

      // Named exports correspond to step types
      for (const [stepType, options] of Object.entries(optionsModule)) {
        if (
          stepType !== "default" &&
          typeof options === "object" &&
          options !== null
        ) {
          stepOptions[stepType] = options as Record<string, unknown>;
          this.log.info(
            `Auto-detected centralized options: ${stepType} from step-options.ts`,
          );
        }
      }
    } catch (error) {
      // step-options.ts is optional
    }

    // 2. Load inline options from custom step files
    const customStepPattern = this.config.testing.custom_step_pattern;
    const tsFiles = await glob(path.join(directory, customStepPattern), {
      ignore: ["**/*.spec.ts", "**/step-options.ts"],
    });

    for (const tsFile of tsFiles) {
      try {
        const module = await import(tsFile);
        const fileName = path.basename(tsFile);

        // If there's an export named "options"
        if (module.options && typeof module.options === "object") {
          // Find the corresponding step class to determine step type
          let foundStepClasses = 0;
          for (const [, exportValue] of Object.entries(module)) {
            if (this.isStepClass(exportValue)) {
              const stepType = this.inferStepTypeFromExtends(exportValue);
              if (stepType) {
                foundStepClasses++;

                // If multiple step classes exist in same file, log warning
                if (foundStepClasses > 1) {
                  this.log.warn(
                    `Multiple step classes found in ${fileName}. Inline options will be applied to the first step class only.`,
                  );
                  break;
                }

                // Merge with centralized options (inline has precedence)
                stepOptions[stepType] = {
                  ...stepOptions[stepType],
                  ...module.options,
                };
                this.log.info(
                  `Auto-detected inline options for ${stepType} from ${fileName}`,
                );
              }
            }
          }
        }
      } catch (error) {
        // Log only meaningful errors
        const isModuleNotFound =
          error instanceof Error &&
          "code" in error &&
          error.code === "MODULE_NOT_FOUND";
        const isNodeModules = tsFile.includes("node_modules");

        if (!isModuleNotFound && !isNodeModules) {
          this.log.warn(
            `Failed to import ${path.basename(tsFile)} for options: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      }
    }

    return stepOptions;
  }

  /**
   * Checks if a class extends a specific base class
   * Uses prototype chain inspection
   */
  private extendsClass(childClass: unknown, baseClass: unknown): boolean {
    try {
      // Type guard to ensure childClass and baseClass have prototype
      if (
        !childClass ||
        typeof childClass !== "function" ||
        !baseClass ||
        typeof baseClass !== "function"
      ) {
        return false;
      }

      let proto = (childClass as any).prototype;

      // Walk up the prototype chain
      while (proto) {
        // Direct comparison with base class prototype
        if (proto === (baseClass as any).prototype) {
          return true;
        }

        // Also check constructor reference
        if (proto.constructor === baseClass) {
          return true;
        }

        proto = Object.getPrototypeOf(proto);
      }

      return false;
    } catch (error) {
      this.log.warn(
        `Error checking inheritance for ${(childClass as any)?.name}:`,
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

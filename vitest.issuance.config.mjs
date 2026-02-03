/**
 * Vitest configuration for issuance tests
 * Uses common configuration factory to avoid duplication
 */

import { createTestConfig } from "./vitest.common.mjs";

export default createTestConfig("issuance");

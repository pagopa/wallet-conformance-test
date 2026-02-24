import { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";

export const parseItWalletSpecVersion = (
  version: string,
): version is ItWalletSpecsVersion =>
  Object.values(ItWalletSpecsVersion).includes(version as ItWalletSpecsVersion);

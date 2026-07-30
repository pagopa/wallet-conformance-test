import { randomUUID } from "node:crypto";
import {
  chmodSync,
  existsSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { z } from "zod";

import type { KeyPair, KeyPairJwk } from "@/types";

import { ensureDir } from "./utils";

export interface CredentialResponseBackup {
  access_token: string;
  dpop_jwk: KeyPairJwk;
  notification_id?: string;
  refresh_token?: string;
  transaction_id?: string;
}

export type CredentialResponseBackupIdentifierType =
  | "notification_id"
  | "transaction_id";

export type CredentialResponseBackupOperation =
  | "ensure_directory"
  | "parse_file"
  | "read_file"
  | "validate_content"
  | "validate_identifier"
  | "write_file";

export class CredentialResponseBackupPersistenceError extends Error {
  readonly identifierType: CredentialResponseBackupIdentifierType;
  readonly operation: CredentialResponseBackupOperation;
  readonly safePath: string;

  constructor({
    cause,
    identifierType,
    operation,
    safePath,
  }: {
    cause?: unknown;
    identifierType: CredentialResponseBackupIdentifierType;
    operation: CredentialResponseBackupOperation;
    safePath: string;
  }) {
    const causeMessage =
      cause instanceof Error
        ? cause.message
        : cause
          ? String(cause)
          : undefined;
    super(
      `Credential response backup failed during ${operation} for ${identifierType} at '${safePath}'` +
        (causeMessage ? `: ${causeMessage}` : ""),
    );
    this.name = "CredentialResponseBackupPersistenceError";
    this.identifierType = identifierType;
    this.operation = operation;
    this.safePath = safePath;
  }
}

export function saveCredentialResponseBackup(
  backupStoragePath: string,
  backup: CredentialResponseBackup,
): string[] {
  const targets: {
    identifier: string | undefined;
    identifierType: CredentialResponseBackupIdentifierType;
    subdirectory: string;
  }[] = [
    {
      identifier: backup.transaction_id,
      identifierType: "transaction_id",
      subdirectory: "transactions",
    },
    {
      identifier: backup.notification_id,
      identifierType: "notification_id",
      subdirectory: "notifications",
    },
  ];

  const selectedTargets = targets.filter(
    (target): target is (typeof targets)[number] & { identifier: string } =>
      target.identifier !== undefined,
  );
  if (selectedTargets.length === 0) return [];

  const payload = `${JSON.stringify(backup, null, 2)}\n`;

  return selectedTargets.map((target) => {
    const directory = path.join(backupStoragePath, target.subdirectory);
    ensureBackupDirectory(directory, target.identifierType);
    const filePath = buildSafeBackupPath(
      directory,
      target.identifier,
      target.identifierType,
    );
    writeBackupFile(filePath, payload, target.identifierType);
    return filePath;
  });
}

const privateDpopJwkSchema = z
  .object({
    alg: z.literal("ES256"),
    crv: z.literal("P-256"),
    d: z.string().min(1),
    kid: z.string().min(1),
    kty: z.literal("EC"),
    x: z.string().min(1),
    y: z.string().min(1),
  })
  .passthrough();

const loadableBackupSchema = z
  .object({
    access_token: z.string().optional(),
    dpop_jwk: privateDpopJwkSchema,
    notification_id: z.string().optional(),
    refresh_token: z.string().min(1),
    transaction_id: z.string().optional(),
  })
  .passthrough();

export type DeferredTransactionBackup = z.infer<typeof loadableBackupSchema> & {
  dPoPKey: KeyPair;
};

export type ReissuanceNotificationBackup = z.infer<
  typeof loadableBackupSchema
> & {
  dPoPKey: KeyPair;
};

export function loadNotificationCredentialResponseBackup(
  backupStoragePath: string,
  notificationId: string,
): ReissuanceNotificationBackup {
  return loadCredentialResponseBackup({
    backupStoragePath,
    expectedIdentifierField: "notification_id",
    identifier: notificationId,
    identifierType: "notification_id",
    subdirectory: "notifications",
  });
}

export function loadTransactionCredentialResponseBackup(
  backupStoragePath: string,
  transactionId: string,
): DeferredTransactionBackup {
  return loadCredentialResponseBackup({
    backupStoragePath,
    expectedIdentifierField: "transaction_id",
    identifier: transactionId,
    identifierType: "transaction_id",
    subdirectory: "transactions",
  });
}

function assertSafeIdentifier(identifier: string): void {
  if (identifier.trim().length === 0) {
    throw new Error("identifier must not be empty");
  }
  if (identifier === "." || identifier === "..") {
    throw new Error("identifier must not be a relative path segment");
  }
  if (
    identifier.includes(path.posix.sep) ||
    identifier.includes(path.win32.sep)
  ) {
    throw new Error("identifier must not contain path separators");
  }
  if (path.isAbsolute(identifier) || path.win32.isAbsolute(identifier)) {
    throw new Error("identifier must not be an absolute path");
  }
}

function buildSafeBackupPath(
  directory: string,
  identifier: string,
  identifierType: CredentialResponseBackupIdentifierType,
): string {
  const safeDirectory = path.resolve(directory);
  try {
    assertSafeIdentifier(identifier);
    const filePath = path.resolve(safeDirectory, `${identifier}.json`);
    const relativePath = path.relative(safeDirectory, filePath);
    if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
      throw new Error("identifier resolves outside the backup directory");
    }
    return filePath;
  } catch (cause) {
    throw new CredentialResponseBackupPersistenceError({
      cause,
      identifierType,
      operation: "validate_identifier",
      safePath: safeDirectory,
    });
  }
}

function ensureBackupDirectory(
  directory: string,
  identifierType: CredentialResponseBackupIdentifierType,
): void {
  try {
    ensureDir(directory);
  } catch (cause) {
    throw new CredentialResponseBackupPersistenceError({
      cause,
      identifierType,
      operation: "ensure_directory",
      safePath: path.resolve(directory),
    });
  }
}

function loadCredentialResponseBackup({
  backupStoragePath,
  expectedIdentifierField,
  identifier,
  identifierType,
  subdirectory,
}: {
  backupStoragePath: string;
  expectedIdentifierField: CredentialResponseBackupIdentifierType;
  identifier: string;
  identifierType: CredentialResponseBackupIdentifierType;
  subdirectory: string;
}): z.infer<typeof loadableBackupSchema> & { dPoPKey: KeyPair } {
  const directory = path.join(backupStoragePath, subdirectory);
  const filePath = buildSafeBackupPath(directory, identifier, identifierType);
  let payload: string;
  try {
    payload = readFileSync(filePath, "utf8");
  } catch (cause) {
    throw new CredentialResponseBackupPersistenceError({
      cause,
      identifierType,
      operation: "read_file",
      safePath: filePath,
    });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch (cause) {
    throw new CredentialResponseBackupPersistenceError({
      cause,
      identifierType,
      operation: "parse_file",
      safePath: filePath,
    });
  }

  const validation = loadableBackupSchema.safeParse(parsed);
  if (!validation.success) {
    throw new CredentialResponseBackupPersistenceError({
      cause: new Error(`${identifierType} backup content is invalid`),
      identifierType,
      operation: "validate_content",
      safePath: filePath,
    });
  }

  const payloadIdentifier = validation.data[expectedIdentifierField];
  if (payloadIdentifier !== undefined && payloadIdentifier !== identifier) {
    throw new CredentialResponseBackupPersistenceError({
      cause: new Error(
        `${expectedIdentifierField} does not match requested identifier`,
      ),
      identifierType,
      operation: "validate_content",
      safePath: filePath,
    });
  }

  const privateKey = validation.data.dpop_jwk;
  const publicKey = {
    alg: privateKey.alg,
    crv: privateKey.crv,
    kid: privateKey.kid,
    kty: privateKey.kty,
    x: privateKey.x,
    y: privateKey.y,
  } as KeyPairJwk;

  return {
    ...validation.data,
    dPoPKey: {
      privateKey: privateKey as KeyPairJwk,
      publicKey,
    },
  };
}

function writeBackupFile(
  filePath: string,
  payload: string,
  identifierType: CredentialResponseBackupIdentifierType,
): void {
  const tempPath = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${process.pid}.${randomUUID()}.tmp`,
  );

  try {
    writeFileSync(tempPath, payload, { mode: 0o600 });
    chmodSync(tempPath, 0o600);
    renameSync(tempPath, filePath);
    chmodSync(filePath, 0o600);
  } catch (cause) {
    if (existsSync(tempPath)) {
      rmSync(tempPath, { force: true });
    }
    throw new CredentialResponseBackupPersistenceError({
      cause,
      identifierType,
      operation: "write_file",
      safePath: filePath,
    });
  }
}

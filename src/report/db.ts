import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { resolvePackageAssetPath } from "@/logic/runtime-paths";

export function openDb(dbPath: string): DatabaseSync {
  if (dbPath !== ":memory:") {
    mkdirSync(dirname(dbPath), { recursive: true });
  }

  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;");
  initSchema(db);
  return db;
}

export function resolveDbPath(): string {
  return resolvePackageAssetPath("data/wct.db");
}

function initSchema(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id          TEXT PRIMARY KEY,
      started_at  TEXT NOT NULL,
      closed_at   TEXT,
      entity_name TEXT NOT NULL DEFAULT '-',
      phase       TEXT NOT NULL,
      status      TEXT NOT NULL DEFAULT 'OPEN'
    );

    CREATE TABLE IF NOT EXISTS checks (
      id             TEXT PRIMARY KEY,
      session_id     TEXT NOT NULL REFERENCES sessions(id),
      requirement_id TEXT NOT NULL,
      description    TEXT NOT NULL,
      phase          TEXT NOT NULL,
      result         TEXT NOT NULL,
      timestamp      TEXT NOT NULL,
      error_message  TEXT
    );
  `);
}

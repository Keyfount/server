/**
 * SQLite store. WAL mode, FK enforcement, busy-timeout sane.
 * One connection per process — better-sqlite3 is synchronous; we lean on
 * Fastify's event loop instead of a pool.
 */
import Database, { type Database as DB } from "better-sqlite3";
import { chmodSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface Store {
  db: DB;
  close(): void;
}

export function openStore(databasePath: string): Store {
  const db = new Database(databasePath);
  // Restrict the DB file to its owner. It holds linkable metadata
  // (email_hash, device labels, IP HMACs, the OPRF seed + AKE keypair), so
  // on a shared host or a loose bind-mount it must not be world-readable.
  // The -wal/-shm siblings are gated by the data dir's 0700 mode (set when
  // the dir is created in buildServices). Best effort: :memory: has no file
  // and some filesystems reject chmod.
  if (databasePath !== ":memory:") {
    try {
      chmodSync(databasePath, 0o600);
    } catch {
      /* non-POSIX or read-only mount: fall back to the dir's protection */
    }
  }
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  db.pragma("foreign_keys = ON");
  db.pragma("busy_timeout = 5000");
  db.pragma("temp_store = MEMORY");
  return { db, close: () => db.close() };
}

/**
 * Apply migrations from migrations/*.sql in lexicographic order. Each file
 * runs in a single transaction so a partial failure cannot leave us in a
 * half-migrated state.
 *
 * Migration files are bundled at build time — we read them from the
 * `migrations/` directory shipped alongside `dist/`.
 */
export function migrate(db: DB, migrationsDir?: string): { applied: number[] } {
  // dist/store/db.js → ../../migrations
  const dir =
    migrationsDir ?? path.resolve(__dirname, "..", "..", "migrations");

  db.exec(
    "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL) STRICT",
  );

  const already = new Set<number>(
    (
      db.prepare("SELECT version FROM schema_migrations").all() as {
        version: number;
      }[]
    ).map((r) => r.version),
  );

  const files = readdirSync(dir)
    .filter((f) => /^\d+_.+\.sql$/.test(f))
    .sort();

  const applied: number[] = [];
  for (const file of files) {
    const version = Number.parseInt(file.split("_", 1)[0]!, 10);
    if (already.has(version)) continue;
    const sql = readFileSync(path.join(dir, file), "utf8");
    const tx = db.transaction(() => {
      db.exec(sql);
      db.prepare(
        "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
      ).run(version, Date.now());
    });
    tx();
    applied.push(version);
  }
  return { applied };
}

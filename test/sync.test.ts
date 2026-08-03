/**
 * Integration tests for the sync layer. We don't validate AES-GCM
 * end-to-end here (that's the client's job); we feed the server random
 * byte payloads and check ordering, ownership, cursor semantics, size
 * limits, and snapshot+compaction.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import type { FastifyInstance } from "fastify";
import { OpaqueClient, OpaqueID, getOpaqueConfig, RegistrationResponse, KE2 } from "@cloudflare/opaque-ts";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

import { buildApp } from "../src/app.js";
import type { Config } from "../src/config/env.js";
import { SYNC_LIMITS } from "../src/store/sync.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = path.resolve(__dirname, "..", "migrations");
const opaqueConfig = getOpaqueConfig(OpaqueID.OPAQUE_P256);

const testConfig = (): Config => ({
  port: 0,
  host: "127.0.0.1",
  databasePath: ":memory:",
  logLevel: "fatal",
  trustProxy: false,
  adminPort: null,
  adminHost: "127.0.0.1",
  corsOrigins: [],
  serverHmacKey: Buffer.alloc(32, 1),
});

async function registerAndLogin(
  app: FastifyInstance,
  email: string,
  master: string,
): Promise<string> {
  const client = new OpaqueClient(opaqueConfig);
  const req = await client.registerInit(master);
  if (req instanceof Error) throw req;
  const startRes = await app.inject({
    method: "POST",
    url: "/auth/opaque/register/start",
    payload: { email, request: req.serialize() },
  });
  const startBody = startRes.json() as { response: number[] };
  const fin = await client.registerFinish(
    RegistrationResponse.deserialize(opaqueConfig, startBody.response),
    "keyfount-server",
  );
  if (fin instanceof Error) throw fin;
  const finRes = await app.inject({
    method: "POST",
    url: "/auth/opaque/register/finish",
    payload: {
      email,
      record: fin.record.serialize(),
      kdfParams: JSON.stringify({ algo: "argon2id", m: 65536, t: 3, p: 1 }),
      devicePubkey: Array.from(randomBytes(32)),
    },
  });
  const finBody = finRes.json() as { userId: string };
  // Skip the admin workflow by approving directly in the DB.
   
  const db = (app as any).__store_db as import("better-sqlite3").Database;
  db.prepare("UPDATE users SET approval_status = 'approved' WHERE id = ?").run(
    Buffer.from(finBody.userId, "hex"),
  );
  const statusRes = await app.inject({
    method: "GET",
    url: `/auth/approval-status/${finBody.userId}`,
  });
  return (statusRes.json() as { sessionToken: string }).sessionToken;
}

async function pushEvent(
  app: FastifyInstance,
  token: string,
  lamport: number,
  size = 64,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const r = await app.inject({
    method: "POST",
    url: "/events",
    headers: { authorization: `Bearer ${token}` },
    payload: {
      lamport,
      ciphertext: Array.from(randomBytes(size)),
      nonce: Array.from(randomBytes(12)),
    },
  });
  return { status: r.statusCode, body: r.json() as Record<string, unknown> };
}

describe("sync events + snapshots", () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp(testConfig(), { migrationsDir: MIGRATIONS_DIR });
  });

  afterAll(async () => {
    await app.close();
  });

  describe("auth gating", () => {
    it("rejects /events without Bearer", async () => {
      const r = await app.inject({ method: "GET", url: "/events" });
      expect(r.statusCode).toBe(401);
    });
    it("rejects POST /events without Bearer", async () => {
      const r = await app.inject({ method: "POST", url: "/events", payload: {} });
      expect(r.statusCode).toBe(401);
    });
    it("rejects /snapshots/latest without Bearer", async () => {
      const r = await app.inject({ method: "GET", url: "/snapshots/latest" });
      expect(r.statusCode).toBe(401);
    });
  });

  describe("event log", () => {
    let token: string;

    beforeEach(async () => {
      await app.close();
      app = await buildApp(testConfig(), { migrationsDir: MIGRATIONS_DIR });
      token = await registerAndLogin(app, `e2e-${Math.random()}@example.com`, "pw");
    });

    it("returns empty list on a brand-new account", async () => {
      const r = await app.inject({
        method: "GET",
        url: "/events",
        headers: { authorization: `Bearer ${token}` },
      });
      expect(r.statusCode).toBe(200);
      const body = r.json() as { events: unknown[]; nextCursor: number; hasMore: boolean };
      expect(body.events).toEqual([]);
      expect(body.nextCursor).toBe(0);
      expect(body.hasMore).toBe(false);
    });

    it("appends events and assigns monotonic server_seq", async () => {
      const r1 = await pushEvent(app, token, 1);
      const r2 = await pushEvent(app, token, 2);
      const r3 = await pushEvent(app, token, 3);
      expect(r1.status).toBe(200);
      expect(r2.status).toBe(200);
      expect(r3.status).toBe(200);
      const seq1 = r1.body["serverSeq"] as number;
      const seq2 = r2.body["serverSeq"] as number;
      const seq3 = r3.body["serverSeq"] as number;
      expect(seq2).toBeGreaterThan(seq1);
      expect(seq3).toBeGreaterThan(seq2);
    });

    it("supports incremental pull with `since`", async () => {
      await pushEvent(app, token, 1);
      const r2 = await pushEvent(app, token, 2);
      const seq2 = r2.body["serverSeq"] as number;
      const list = await app.inject({
        method: "GET",
        url: `/events?since=${seq2}`,
        headers: { authorization: `Bearer ${token}` },
      });
      expect(list.statusCode).toBe(200);
      const body = list.json() as { events: { serverSeq: number }[]; hasMore: boolean };
      expect(body.events).toEqual([]); // nothing after seq2
      await pushEvent(app, token, 3);
      const list2 = await app.inject({
        method: "GET",
        url: `/events?since=${seq2}`,
        headers: { authorization: `Bearer ${token}` },
      });
      const body2 = list2.json() as { events: { serverSeq: number }[] };
      expect(body2.events).toHaveLength(1);
    });

    it("rejects payloads above the per-event limit", async () => {
      const r = await pushEvent(app, token, 1, SYNC_LIMITS.maxEventBytes + 1);
      // 400 from Fastify schema (maxItems) OR 413 from repo
      expect([400, 413]).toContain(r.status);
    });

    it("isolates events between users", async () => {
      const tokenA = token;
      const tokenB = await registerAndLogin(app, `iso-${Math.random()}@example.com`, "pw");
      await pushEvent(app, tokenA, 1);
      const listB = await app.inject({
        method: "GET",
        url: "/events",
        headers: { authorization: `Bearer ${tokenB}` },
      });
      const bodyB = listB.json() as { events: unknown[] };
      expect(bodyB.events).toEqual([]);
    });
  });

  // The relay is zero-knowledge: every payload is an opaque client-side
  // AES-GCM ciphertext. The cross-repo `linkedDomains` feature changes the
  // *plaintext* shape clients encrypt, so by design the relay needs no code
  // change — these tests codify that invariant so a regression that made the
  // relay inspect or size-reject array-bearing payloads can't pass silently.
  // See Keyfount/desktop#72 and Keyfount/extension#91.
  describe("linkedDomains payload — zero-knowledge non-regression (#38)", () => {
    let token: string;

    beforeEach(async () => {
      await app.close();
      app = await buildApp(testConfig(), { migrationsDir: MIGRATIONS_DIR });
      token = await registerAndLogin(app, `ld-${Math.random()}@example.com`, "pw");
    });

    async function pushBytes(ciphertext: number[], lamport: number) {
      const r = await app.inject({
        method: "POST",
        url: "/events",
        headers: { authorization: `Bearer ${token}` },
        payload: { lamport, ciphertext, nonce: Array.from(randomBytes(12)) },
      });
      return { status: r.statusCode, body: r.json() as Record<string, unknown> };
    }

    async function pullAll(): Promise<{ ciphertext: number[]; serverSeq: number }[]> {
      const r = await app.inject({
        method: "GET",
        url: "/events",
        headers: { authorization: `Bearer ${token}` },
      });
      return (r.json() as { events: { ciphertext: number[]; serverSeq: number }[] }).events;
    }

    it("round-trips an opaque linkedDomains-bearing payload byte-for-byte", async () => {
      // Stand-in for the ciphertext bytes a client produces by AES-GCM-
      // encrypting an `upsert_account` op whose entry carries linkedDomains.
      // The relay never decrypts it — the contract is "same bytes back".
      const opaque = Array.from(
        new TextEncoder().encode(
          JSON.stringify({
            t: "upsert_account",
            entry: {
              domain: "w.example.com",
              username: "u@example.com",
              linkedDomains: ["z.example.com", "other-site.com"],
              profile: { mode: "random", length: 16, counter: 1 },
              createdAt: 1,
              lastUsedAt: 2,
            },
          }),
        ),
      );
      const push = await pushBytes(opaque, 1);
      expect(push.status).toBe(200);

      const events = await pullAll();
      expect(events).toHaveLength(1);
      expect(events[0]!.ciphertext).toEqual(opaque);
    });

    it("round-trips a larger ciphertext (extra linked domains) unchanged", async () => {
      const size = Math.min(4096, SYNC_LIMITS.maxEventBytes - 1);
      const big = Array.from(randomBytes(size));
      expect(big.length).toBeLessThan(SYNC_LIMITS.maxEventBytes);

      const push = await pushBytes(big, 1);
      expect(push.status).toBe(200);

      const events = await pullAll();
      expect(events).toHaveLength(1);
      expect(events[0]!.ciphertext).toEqual(big);
      expect(events[0]!.ciphertext).toHaveLength(size);
    });
  });

  describe("snapshots", () => {
    let token: string;

    beforeEach(async () => {
      await app.close();
      app = await buildApp(testConfig(), { migrationsDir: MIGRATIONS_DIR });
      token = await registerAndLogin(app, `snap-${Math.random()}@example.com`, "pw");
    });

    it("returns 204 when there is no snapshot yet", async () => {
      const r = await app.inject({
        method: "GET",
        url: "/snapshots/latest",
        headers: { authorization: `Bearer ${token}` },
      });
      expect(r.statusCode).toBe(204);
    });

    it("uploads a snapshot and compacts older events", async () => {
      const e1 = await pushEvent(app, token, 1);
      const e2 = await pushEvent(app, token, 2);
      const seqAfter = e2.body["serverSeq"] as number;
      void e1;

      const put = await app.inject({
        method: "POST",
        url: "/snapshots",
        headers: { authorization: `Bearer ${token}` },
        payload: {
          upToSeq: seqAfter,
          ciphertext: Array.from(randomBytes(128)),
          nonce: Array.from(randomBytes(12)),
        },
      });
      expect(put.statusCode).toBe(200);
      const putBody = put.json() as { snapshotId: string; compactedEvents: number };
      expect(putBody.compactedEvents).toBe(2);

      const listAfter = await app.inject({
        method: "GET",
        url: "/events",
        headers: { authorization: `Bearer ${token}` },
      });
      const bodyAfter = listAfter.json() as { events: unknown[] };
      expect(bodyAfter.events).toEqual([]);

      const latest = await app.inject({
        method: "GET",
        url: "/snapshots/latest",
        headers: { authorization: `Bearer ${token}` },
      });
      expect(latest.statusCode).toBe(200);
      const latestBody = latest.json() as { upToSeq: number };
      expect(latestBody.upToSeq).toBe(seqAfter);
    });

    it("rejects a snapshot ahead of the log", async () => {
      const r = await app.inject({
        method: "POST",
        url: "/snapshots",
        headers: { authorization: `Bearer ${token}` },
        payload: {
          upToSeq: 99999,
          ciphertext: Array.from(randomBytes(64)),
          nonce: Array.from(randomBytes(12)),
        },
      });
      expect(r.statusCode).toBe(400);
      expect((r.json() as { error: string }).error).toBe("snapshot_ahead_of_log");
    });
  });
});

// referenced to avoid unused warning when adding type imports
void KE2;

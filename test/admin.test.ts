/**
 * Admin OPAQUE setup + approval workflow. Drives the full client/server
 * handshake the same way auth.test.ts does for users, then exercises
 * the gate: a freshly-registered user MUST be pending, admin approve →
 * polling returns a session, login through that user is now allowed.
 */
import { describe, it, expect, afterAll, beforeEach } from "vitest";
import type { FastifyInstance } from "fastify";
import {
  KE2,
  OpaqueClient,
  OpaqueID,
  RegistrationResponse,
  getOpaqueConfig,
} from "@cloudflare/opaque-ts";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

import { buildApp } from "../src/app.js";
import type { Config } from "../src/config/env.js";

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

async function setupAdmin(
  app: FastifyInstance,
  username: string,
  password: string,
): Promise<{ adminId: string; sessionToken: string }> {
  const client = new OpaqueClient(opaqueConfig);
  const req = await client.registerInit(password);
  if (req instanceof Error) throw req;
  const start = await app.inject({
    method: "POST",
    url: "/admin/setup/register/start",
    payload: { username, request: req.serialize() },
  });
  expect(start.statusCode).toBe(200);
  const { response } = start.json() as { response: number[] };
  const fin = await client.registerFinish(
    RegistrationResponse.deserialize(opaqueConfig, response),
    "keyfount-server",
  );
  if (fin instanceof Error) throw fin;
  const finRes = await app.inject({
    method: "POST",
    url: "/admin/setup/register/finish",
    payload: { username, record: fin.record.serialize() },
  });
  expect(finRes.statusCode).toBe(200);
  return finRes.json() as { adminId: string; sessionToken: string };
}

async function adminLogin(
  app: FastifyInstance,
  username: string,
  password: string,
): Promise<string> {
  const client = new OpaqueClient(opaqueConfig);
  const ke1 = await client.authInit(password);
  if (ke1 instanceof Error) throw ke1;
  const start = await app.inject({
    method: "POST",
    url: "/admin/auth/login/start",
    payload: { username, ke1: ke1.serialize() },
  });
  expect(start.statusCode).toBe(200);
  const startBody = start.json() as { ke2: number[]; challengeToken: string };
  const finResult = await client.authFinish(
    KE2.deserialize(opaqueConfig, startBody.ke2),
    "keyfount-server",
  );
  if (finResult instanceof Error) throw finResult;
  const fin = await app.inject({
    method: "POST",
    url: "/admin/auth/login/finish",
    payload: {
      challengeToken: startBody.challengeToken,
      ke3: finResult.ke3.serialize(),
    },
  });
  expect(fin.statusCode).toBe(200);
  return (fin.json() as { sessionToken: string }).sessionToken;
}

/** Drive a failed admin login (wrong password) end to end and return the
 * status of the call that failed, so a test can assert the lockout. */
async function failedAdminLogin(
  app: FastifyInstance,
  username: string,
  wrongPassword: string,
): Promise<number> {
  const client = new OpaqueClient(opaqueConfig);
  const ke1 = await client.authInit(wrongPassword);
  if (ke1 instanceof Error) throw ke1;
  const start = await app.inject({
    method: "POST",
    url: "/admin/auth/login/start",
    payload: { username, ke1: ke1.serialize() },
  });
  if (start.statusCode !== 200) return start.statusCode;
  const startBody = start.json() as { ke2: number[]; challengeToken: string };
  const fin = await client.authFinish(
    KE2.deserialize(opaqueConfig, startBody.ke2),
    "keyfount-server",
  );
  const ke3 =
    fin instanceof Error
      ? new Array(opaqueConfig.mac.Nm).fill(0)
      : fin.ke3.serialize();
  const finRes = await app.inject({
    method: "POST",
    url: "/admin/auth/login/finish",
    payload: { challengeToken: startBody.challengeToken, ke3 },
  });
  return finRes.statusCode;
}

async function userRegister(
  app: FastifyInstance,
  email: string,
  master: string,
): Promise<{ userId: string }> {
  const client = new OpaqueClient(opaqueConfig);
  const req = await client.registerInit(master);
  if (req instanceof Error) throw req;
  const start = await app.inject({
    method: "POST",
    url: "/auth/opaque/register/start",
    payload: { email, request: req.serialize() },
  });
  const { response } = start.json() as { response: number[] };
  const fin = await client.registerFinish(
    RegistrationResponse.deserialize(opaqueConfig, response),
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
  expect(finRes.statusCode).toBe(200);
  const body = finRes.json() as { userId: string; approvalStatus: string };
  expect(body.approvalStatus).toBe("pending");
  return { userId: body.userId };
}

describe("admin + approval workflow", () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    app = await buildApp(testConfig(), { migrationsDir: MIGRATIONS_DIR });
  });

  afterAll(async () => {
    if (app) await app.close();
  });

  describe("setup", () => {
    it("reports adminExists=false on a brand-new instance", async () => {
      const r = await app.inject({ method: "GET", url: "/admin/state" });
      expect(r.statusCode).toBe(200);
      expect(r.json()).toEqual({ adminExists: false });
    });

    it("creates the first admin and returns a session", async () => {
      const { adminId, sessionToken } = await setupAdmin(
        app,
        "root",
        "pw-very-strong-1",
      );
      expect(adminId).toMatch(/^[0-9a-f]{32}$/);
      expect(sessionToken).toMatch(/^[A-Za-z0-9_-]+$/);
      const after = await app.inject({ method: "GET", url: "/admin/state" });
      expect(after.json()).toEqual({ adminExists: true });
    });

    it("locks out further setup once an admin exists", async () => {
      await setupAdmin(app, "root", "pw-1");
      const client = new OpaqueClient(opaqueConfig);
      const req = await client.registerInit("anything");
      if (req instanceof Error) throw req;
      const r = await app.inject({
        method: "POST",
        url: "/admin/setup/register/start",
        payload: { username: "intruder", request: req.serialize() },
      });
      expect(r.statusCode).toBe(403);
    });
  });

  describe("login", () => {
    beforeEach(async () => {
      await setupAdmin(app, "root", "pw-1");
    });

    it("logs in with the correct password and exposes /admin/me", async () => {
      const token = await adminLogin(app, "root", "pw-1");
      const me = await app.inject({
        method: "GET",
        url: "/admin/me",
        headers: { authorization: `Bearer ${token}` },
      });
      expect(me.statusCode).toBe(200);
      expect((me.json() as { username: string }).username).toBe("root");
    });

    it("rejects wrong password with a generic 401", async () => {
      const client = new OpaqueClient(opaqueConfig);
      const ke1 = await client.authInit("not-the-real-one");
      if (ke1 instanceof Error) throw ke1;
      const start = await app.inject({
        method: "POST",
        url: "/admin/auth/login/start",
        payload: { username: "root", ke1: ke1.serialize() },
      });
      const startBody = start.json() as {
        ke2: number[];
        challengeToken: string;
      };
      const fin = await client.authFinish(
        KE2.deserialize(opaqueConfig, startBody.ke2),
        "keyfount-server",
      );
      // Client refuses; we still POST a fabricated ke3 to confirm the
      // server returns the generic 401 envelope.
      const ke3 =
        fin instanceof Error
          ? new Array(opaqueConfig.mac.Nm).fill(0)
          : fin.ke3.serialize();
      const finRes = await app.inject({
        method: "POST",
        url: "/admin/auth/login/finish",
        payload: { challengeToken: startBody.challengeToken, ke3 },
      });
      expect(finRes.statusCode).toBe(401);
      expect(finRes.json()).toEqual({ error: "invalid_login" });
    });

    it("rate-limits admin login after five failed attempts", async () => {
      for (let i = 0; i < 5; i++) {
        expect(await failedAdminLogin(app, "root", `wrong-${i}`)).toBe(401);
      }
      // The sixth attempt is blocked at /start before any OPAQUE work.
      const client = new OpaqueClient(opaqueConfig);
      const ke1 = await client.authInit("wrong-again");
      if (ke1 instanceof Error) throw ke1;
      const start = await app.inject({
        method: "POST",
        url: "/admin/auth/login/start",
        payload: { username: "root", ke1: ke1.serialize() },
      });
      expect(start.statusCode).toBe(429);
      expect(start.headers["retry-after"]).toBeDefined();
    });

    it("rejects /admin/me without a session", async () => {
      const r = await app.inject({ method: "GET", url: "/admin/me" });
      expect(r.statusCode).toBe(401);
    });
  });

  describe("approval workflow", () => {
    let token: string;

    beforeEach(async () => {
      await setupAdmin(app, "root", "pw-1");
      token = await adminLogin(app, "root", "pw-1");
    });

    it("listing pending shows newly-registered users", async () => {
      await userRegister(app, "alice@example.com", "her-master");
      const list = await app.inject({
        method: "GET",
        url: "/admin/users/pending",
        headers: { authorization: `Bearer ${token}` },
      });
      expect(list.statusCode).toBe(200);
      const body = list.json() as { users: { id: string }[] };
      expect(body.users).toHaveLength(1);
    });

    it("approving a pending user transitions /auth/approval-status to approved", async () => {
      const { userId } = await userRegister(
        app,
        "bob@example.com",
        "his-master",
      );
      let status = await app.inject({
        method: "GET",
        url: `/auth/approval-status/${userId}`,
      });
      expect((status.json() as { status: string }).status).toBe("pending");

      const approve = await app.inject({
        method: "POST",
        url: `/admin/users/${userId}/approve`,
        headers: { authorization: `Bearer ${token}` },
      });
      expect(approve.statusCode).toBe(200);

      status = await app.inject({
        method: "GET",
        url: `/auth/approval-status/${userId}`,
      });
      const body = status.json() as { status: string; sessionToken?: string };
      expect(body.status).toBe("approved");
      expect(body.sessionToken).toBeDefined();
    });

    it("rejecting a user surfaces the reason on /auth/approval-status", async () => {
      const { userId } = await userRegister(
        app,
        "carl@example.com",
        "his-master",
      );
      const reject = await app.inject({
        method: "POST",
        url: `/admin/users/${userId}/reject`,
        headers: { authorization: `Bearer ${token}` },
        payload: { reason: "Demande non sollicitée" },
      });
      expect(reject.statusCode).toBe(200);
      const status = await app.inject({
        method: "GET",
        url: `/auth/approval-status/${userId}`,
      });
      const body = status.json() as { status: string; reason?: string };
      expect(body.status).toBe("rejected");
      expect(body.reason).toBe("Demande non sollicitée");
    });

    it("returns 'pending' for an unknown userId (no enumeration)", async () => {
      const fakeId = randomBytes(16).toString("hex");
      const r = await app.inject({
        method: "GET",
        url: `/auth/approval-status/${fakeId}`,
      });
      expect(r.statusCode).toBe(200);
      expect(r.json()).toEqual({ status: "pending" });
    });

    it("blocks login until approved", async () => {
      await userRegister(app, "dave@example.com", "his-master");
      // Try a normal login flow; should fail at /login/finish with 403
      const client = new OpaqueClient(opaqueConfig);
      const ke1 = await client.authInit("his-master");
      if (ke1 instanceof Error) throw ke1;
      const start = await app.inject({
        method: "POST",
        url: "/auth/opaque/login/start",
        payload: { email: "dave@example.com", ke1: ke1.serialize() },
      });
      const startBody = start.json() as {
        ke2: number[];
        challengeToken: string;
      };
      const fin = await client.authFinish(
        KE2.deserialize(opaqueConfig, startBody.ke2),
        "keyfount-server",
      );
      if (fin instanceof Error) throw fin;
      const finRes = await app.inject({
        method: "POST",
        url: "/auth/opaque/login/finish",
        payload: {
          challengeToken: startBody.challengeToken,
          ke3: fin.ke3.serialize(),
          devicePubkey: Array.from(randomBytes(32)),
        },
      });
      expect(finRes.statusCode).toBe(403);
      expect((finRes.json() as { error: string }).error).toBe(
        "pending_approval",
      );
    });
  });

  describe("admin user management endpoints", () => {
    let token: string;

    beforeEach(async () => {
      await setupAdmin(app, "root", "pw-1");
      token = await adminLogin(app, "root", "pw-1");
    });

    it("GET /admin/users with no filter lists everyone with a total", async () => {
      await userRegister(app, "alice@example.com", "pw-a");
      await userRegister(app, "bob@example.com", "pw-b");
      const r = await app.inject({
        method: "GET",
        url: "/admin/users",
        headers: { authorization: `Bearer ${token}` },
      });
      expect(r.statusCode).toBe(200);
      const body = r.json() as { total: number; users: { status: string }[] };
      expect(body.total).toBe(2);
      expect(body.users).toHaveLength(2);
      expect(body.users.every((u) => u.status === "pending")).toBe(true);
    });

    it("GET /admin/users?status=approved excludes pending", async () => {
      const { userId } = await userRegister(app, "alice@example.com", "pw-a");
      await userRegister(app, "bob@example.com", "pw-b");
      // approve alice
      const apr = await app.inject({
        method: "POST",
        url: `/admin/users/${userId}/approve`,
        headers: { authorization: `Bearer ${token}` },
      });
      expect(apr.statusCode).toBe(200);
      const r = await app.inject({
        method: "GET",
        url: "/admin/users?status=approved",
        headers: { authorization: `Bearer ${token}` },
      });
      const body = r.json() as {
        total: number;
        users: { id: string; status: string }[];
      };
      expect(body.total).toBe(1);
      expect(body.users[0]!.id).toBe(userId);
      expect(body.users[0]!.status).toBe("approved");
    });

    it("revoke flips an approved user back to rejected", async () => {
      const { userId } = await userRegister(app, "alice@example.com", "pw-a");
      await app.inject({
        method: "POST",
        url: `/admin/users/${userId}/approve`,
        headers: { authorization: `Bearer ${token}` },
      });
      const r = await app.inject({
        method: "POST",
        url: `/admin/users/${userId}/revoke`,
        headers: { authorization: `Bearer ${token}` },
        payload: { reason: "ne devrait pas être là" },
      });
      expect(r.statusCode).toBe(200);
      const after = await app.inject({
        method: "GET",
        url: "/admin/users?status=rejected",
        headers: { authorization: `Bearer ${token}` },
      });
      const body = after.json() as {
        users: { id: string; rejectionReason?: string }[];
      };
      expect(body.users).toHaveLength(1);
      expect(body.users[0]!.rejectionReason).toBe("ne devrait pas être là");
    });

    it("DELETE /admin/users/:id removes the user", async () => {
      const { userId } = await userRegister(app, "alice@example.com", "pw-a");
      const r = await app.inject({
        method: "DELETE",
        url: `/admin/users/${userId}`,
        headers: { authorization: `Bearer ${token}` },
      });
      expect(r.statusCode).toBe(200);
      const after = await app.inject({
        method: "GET",
        url: "/admin/users?status=all",
        headers: { authorization: `Bearer ${token}` },
      });
      const body = after.json() as { total: number };
      expect(body.total).toBe(0);
    });

    it("DELETE /admin/users/:id returns 404 for an unknown id", async () => {
      const fakeId = randomBytes(16).toString("hex");
      const r = await app.inject({
        method: "DELETE",
        url: `/admin/users/${fakeId}`,
        headers: { authorization: `Bearer ${token}` },
      });
      expect(r.statusCode).toBe(404);
    });

    it("rejects all user-mgmt endpoints without an admin Bearer", async () => {
      const listing = await app.inject({ method: "GET", url: "/admin/users" });
      expect(listing.statusCode).toBe(401);
      // POST routes still need a valid body before auth runs; we send one
      // to isolate the auth check (400 != 401 would mean schema rejected).
      const revoke = await app.inject({
        method: "POST",
        url: "/admin/users/00000000000000000000000000000000/revoke",
        payload: {},
      });
      expect(revoke.statusCode).toBe(401);
      const del = await app.inject({
        method: "DELETE",
        url: "/admin/users/00000000000000000000000000000000",
      });
      expect(del.statusCode).toBe(401);
    });
  });
});

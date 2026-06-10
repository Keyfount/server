/**
 * Admin endpoints.
 *
 * Authentication uses OPAQUE-3DH, same protocol as the user side but
 * keyed on `admin:<username>` so a user and an admin with the same
 * label can never share a credential. Setup is one-shot: while the
 * `admins` table is empty, anyone can hit /admin/setup/finish to enrol
 * the first (and only) admin. Once a row exists, that endpoint is
 * locked out.
 *
 * Approval gating is admin-only: list pending users, approve, reject.
 * The rejection reason is optional and surfaced to the user via
 * /auth/approval-status.
 */
import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";

import type { OpaqueService } from "../auth/opaque.js";
import type { AdminChallengeService } from "../auth/admin-challenges.js";
import type { AdminSessionService } from "../auth/admin-sessions.js";
import type { UserListFilter, UserRepo } from "../store/users.js";
import type { SessionService } from "../auth/sessions.js";
import type { AdminRepo } from "../store/admins.js";
import type { AuditLogger } from "../store/audit.js";
import { hmacIp } from "../crypto/hmac.js";
import {
  UNKNOWN_ACCOUNT_KEY,
  type LoginRateLimiter,
} from "../auth/ratelimit.js";

export interface AdminDeps {
  opaque: OpaqueService;
  admins: AdminRepo;
  users: UserRepo;
  sessions: AdminSessionService;
  /** User-side sessions, threaded in so revoking an approved user can
   * also revoke their existing bearer tokens. */
  userSessions: SessionService;
  challenges: AdminChallengeService;
  audit: AuditLogger;
  /** Shared login rate limiter. The admin credential is the highest-value
   * account on the instance, so its login gets the same brute-force
   * protection the user side already has. */
  rateLimit: LoginRateLimiter;
  hmacKey: Buffer;
}

declare module "fastify" {
  interface FastifyRequest {
    admin?: { adminId: Buffer };
  }
}

const BYTES = {
  type: "array",
  items: { type: "integer", minimum: 0, maximum: 255 },
  maxItems: 4096,
} as const;
const USERNAME = { type: "string", minLength: 3, maxLength: 64 } as const;
const TOKEN = { type: "string", minLength: 16, maxLength: 256 } as const;
const cast = (s: object): object => s;

/** Prefix admin credentials so they never collide with user `email_hash`
 * hex strings. */
function credentialId(username: string): string {
  return `admin:${username.trim().toLowerCase()}`;
}

function requireAdmin(sessions: AdminSessionService) {
  return async function (
    req: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    const header = req.headers["authorization"];
    if (typeof header !== "string" || !header.startsWith("Bearer ")) {
      void reply.code(401).send({ error: "unauthorized" });
      return;
    }
    const token = header.slice("Bearer ".length).trim();
    const session = sessions.resolve(token);
    if (!session) {
      void reply.code(401).send({ error: "unauthorized" });
      return;
    }
    req.admin = { adminId: session.adminId };
  };
}

export async function adminRoutes(
  app: FastifyInstance,
  deps: AdminDeps,
): Promise<void> {
  const requireAuth = requireAdmin(deps.sessions);

  // --- GET /admin/state ----------------------------------------------------
  // Public probe so the web UI knows whether to show setup or login.
  app.get("/admin/state", async (_req, reply) => {
    return reply.send({ adminExists: deps.admins.count() > 0 });
  });

  // --- POST /admin/setup/register/start ------------------------------------
  // Only callable while the `admins` table is empty. Drives OPAQUE
  // registration round 1 for the first admin.
  app.post<{
    Body: { username: string; request: number[] };
  }>(
    "/admin/setup/register/start",
    {
      schema: {
        body: cast({
          type: "object",
          required: ["username", "request"],
          properties: { username: USERNAME, request: BYTES },
          additionalProperties: false,
        }),
      },
    },
    async (req, reply) => {
      if (deps.admins.count() > 0) {
        return reply.code(403).send({ error: "setup_locked" });
      }
      try {
        const response = await deps.opaque.registerInit(
          req.body.request,
          credentialId(req.body.username),
        );
        return reply.send({ response });
      } catch {
        return reply.code(400).send({ error: "invalid_request" });
      }
    },
  );

  // --- POST /admin/setup/register/finish -----------------------------------
  app.post<{
    Body: { username: string; record: number[] };
  }>(
    "/admin/setup/register/finish",
    {
      schema: {
        body: cast({
          type: "object",
          required: ["username", "record"],
          properties: { username: USERNAME, record: BYTES },
          additionalProperties: false,
        }),
      },
    },
    async (req, reply) => {
      if (deps.admins.count() > 0) {
        return reply.code(403).send({ error: "setup_locked" });
      }
      try {
        deps.opaque.deserializeRecord(Buffer.from(req.body.record));
      } catch {
        return reply.code(400).send({ error: "invalid_record" });
      }
      const admin = deps.admins.createAdmin({
        username: req.body.username,
        opaqueRecord: Buffer.from(req.body.record),
      });
      const session = deps.sessions.create(admin.id);
      deps.audit.log({
        action: "register",
        ipHash: hmacIp(req.ip, deps.hmacKey),
        metadata: { actor: "admin", username: admin.username },
      });
      return reply.send({
        adminId: admin.id.toString("hex"),
        sessionToken: session.token,
        expiresAt: session.expiresAt,
      });
    },
  );

  // --- POST /admin/auth/login/start ----------------------------------------
  // Anti-enumeration mirrors /auth/opaque/login/start.
  app.post<{
    Body: { username: string; ke1: number[] };
  }>(
    "/admin/auth/login/start",
    {
      schema: {
        body: cast({
          type: "object",
          required: ["username", "ke1"],
          properties: { username: USERNAME, ke1: BYTES },
          additionalProperties: false,
        }),
      },
    },
    async (req, reply) => {
      const admin = deps.admins.findByUsername(req.body.username);

      // Brute-force protection, mirroring the user login path: key on the
      // admin id when known (else a shared unknown bucket) plus the client
      // IP, and check before the costly OPAQUE work.
      const ipHash = hmacIp(req.ip, deps.hmacKey);
      const accountKey = admin ? admin.id : UNKNOWN_ACCOUNT_KEY;
      const rate = deps.rateLimit.check(accountKey, ipHash);
      if (!rate.allowed) {
        return reply
          .code(429)
          .header("Retry-After", Math.ceil(rate.retryAfterMs / 1000))
          .send({ error: "too_many_attempts" });
      }

      let record;
      let isDummy = false;
      if (admin) {
        record = deps.opaque.deserializeRecord(admin.opaqueRecord);
      } else {
        record = await deps.opaque.buildFakeRecord();
        isDummy = true;
      }
      try {
        const { ke2, expected } = await deps.opaque.authInit(
          req.body.ke1,
          record,
          credentialId(req.body.username),
        );
        const challenge = deps.challenges.create(
          admin ? admin.id : null,
          deps.opaque.serializeExpected(expected),
          isDummy,
        );
        return reply.send({ ke2, challengeToken: challenge.token });
      } catch {
        return reply.code(400).send({ error: "invalid_request" });
      }
    },
  );

  // --- POST /admin/auth/login/finish ---------------------------------------
  app.post<{
    Body: { challengeToken: string; ke3: number[] };
  }>(
    "/admin/auth/login/finish",
    {
      schema: {
        body: cast({
          type: "object",
          required: ["challengeToken", "ke3"],
          properties: { challengeToken: TOKEN, ke3: BYTES },
          additionalProperties: false,
        }),
      },
    },
    async (req, reply) => {
      const ipHash = hmacIp(req.ip, deps.hmacKey);
      const challenge = deps.challenges.consume(req.body.challengeToken);
      if (!challenge) {
        return reply.code(401).send({ error: "invalid_login" });
      }
      const accountKey = challenge.adminId ?? UNKNOWN_ACCOUNT_KEY;
      let success = false;
      try {
        const expected = deps.opaque.deserializeExpected(
          challenge.expectedBlob,
        );
        deps.opaque.authFinish(req.body.ke3, expected);
        success = !challenge.isDummy;
      } catch {
        success = false;
      }
      deps.rateLimit.record(accountKey, ipHash, success);
      if (!success || !challenge.adminId) {
        deps.audit.log({
          action: "login_failure",
          ipHash: hmacIp(req.ip, deps.hmacKey),
          metadata: { actor: "admin" },
        });
        return reply.code(401).send({ error: "invalid_login" });
      }
      const session = deps.sessions.create(challenge.adminId);
      deps.audit.log({
        action: "login_success",
        ipHash: hmacIp(req.ip, deps.hmacKey),
        metadata: {
          actor: "admin",
          admin_id: challenge.adminId.toString("hex"),
        },
      });
      return reply.send({
        adminId: challenge.adminId.toString("hex"),
        sessionToken: session.token,
        expiresAt: session.expiresAt,
      });
    },
  );

  // --- POST /admin/auth/logout ---------------------------------------------
  app.post(
    "/admin/auth/logout",
    { preHandler: requireAuth },
    async (req, reply) => {
      const header = req.headers["authorization"];
      if (typeof header === "string" && header.startsWith("Bearer ")) {
        deps.sessions.revoke(header.slice("Bearer ".length).trim());
      }
      return reply.send({ ok: true });
    },
  );

  // --- GET /admin/me -------------------------------------------------------
  // Sanity probe used by the web UI to detect a still-valid session.
  app.get("/admin/me", { preHandler: requireAuth }, async (req, reply) => {
    const admin = deps.admins.findById(req.admin!.adminId);
    if (!admin) return reply.code(401).send({ error: "unauthorized" });
    return reply.send({
      adminId: admin.id.toString("hex"),
      username: admin.username,
    });
  });

  // --- GET /admin/users/pending --------------------------------------------
  app.get<{ Querystring: { limit?: string } }>(
    "/admin/users/pending",
    {
      preHandler: requireAuth,
      schema: {
        querystring: cast({
          type: "object",
          properties: { limit: { type: "string", pattern: "^[0-9]+$" } },
          additionalProperties: false,
        }),
      },
    },
    async (req, reply) => {
      const limit = Math.min(
        500,
        req.query.limit ? Number.parseInt(req.query.limit, 10) : 100,
      );
      const rows = deps.users.listPending(limit);
      return reply.send({
        users: rows.map((u) => ({
          id: u.id.toString("hex"),
          emailHashHex: u.emailHash.toString("hex").slice(0, 16),
          createdAt: u.createdAt,
        })),
      });
    },
  );

  // --- POST /admin/users/:id/approve ---------------------------------------
  app.post<{ Params: { id: string } }>(
    "/admin/users/:id/approve",
    {
      preHandler: requireAuth,
      schema: {
        params: cast({
          type: "object",
          required: ["id"],
          properties: { id: { type: "string", pattern: "^[0-9a-f]{32}$" } },
          additionalProperties: false,
        }),
      },
    },
    async (req, reply) => {
      const userId = Buffer.from(req.params.id, "hex");
      const updated = deps.users.setApprovalStatus({
        userId,
        status: "approved",
        decidedBy: req.admin!.adminId,
      });
      if (!updated) return reply.code(404).send({ error: "user_not_found" });
      deps.audit.log({
        userId,
        action: "register",
        ipHash: hmacIp(req.ip, deps.hmacKey),
        metadata: { actor: "admin", action: "approve" },
      });
      return reply.send({ ok: true });
    },
  );

  // --- POST /admin/users/:id/reject ----------------------------------------
  app.post<{
    Params: { id: string };
    Body: { reason?: string };
  }>(
    "/admin/users/:id/reject",
    {
      preHandler: requireAuth,
      schema: {
        params: cast({
          type: "object",
          required: ["id"],
          properties: { id: { type: "string", pattern: "^[0-9a-f]{32}$" } },
          additionalProperties: false,
        }),
        body: cast({
          type: "object",
          properties: { reason: { type: "string", maxLength: 256 } },
          additionalProperties: false,
        }),
      },
    },
    async (req, reply) => {
      const userId = Buffer.from(req.params.id, "hex");
      const updated = deps.users.setApprovalStatus({
        userId,
        status: "rejected",
        decidedBy: req.admin!.adminId,
        ...(req.body?.reason !== undefined ? { reason: req.body.reason } : {}),
      });
      if (!updated) return reply.code(404).send({ error: "user_not_found" });
      // Revoke any session this user may have already created (defense
      // in depth: pending users normally have no session, but admins can
      // reject an already-approved user).
      deps.userSessions.revokeAllForUser(userId);
      deps.audit.log({
        userId,
        action: "register",
        ipHash: hmacIp(req.ip, deps.hmacKey),
        metadata: { actor: "admin", action: "reject" },
      });
      return reply.send({ ok: true });
    },
  );

  // --- GET /admin/users -----------------------------------------------------
  // Lists every user (or filtered by status) with last-device-activity
  // join. Returns only metadata the admin can act on; never the OPAQUE
  // record or the email itself.
  app.get<{
    Querystring: { status?: string; limit?: string; offset?: string };
  }>(
    "/admin/users",
    {
      preHandler: requireAuth,
      schema: {
        querystring: cast({
          type: "object",
          properties: {
            status: {
              type: "string",
              enum: ["all", "pending", "approved", "rejected"],
            },
            limit: { type: "string", pattern: "^[0-9]+$" },
            offset: { type: "string", pattern: "^[0-9]+$" },
          },
          additionalProperties: false,
        }),
      },
    },
    async (req, reply) => {
      const filter = (req.query.status ?? "all") as UserListFilter;
      const limit = Math.min(
        500,
        req.query.limit !== undefined
          ? Number.parseInt(req.query.limit, 10)
          : 100,
      );
      const offset =
        req.query.offset !== undefined
          ? Number.parseInt(req.query.offset, 10)
          : 0;
      const rows = deps.users.listUsers(filter, limit, offset);
      const total = deps.users.countUsers(filter);
      return reply.send({
        total,
        users: rows.map((u) => ({
          id: u.id.toString("hex"),
          // 8 bytes (16 hex chars) of email_hash so the admin can
          // visually disambiguate users without correlating across
          // servers. Same prefix length as the pending list.
          emailHashHex: u.emailHash.toString("hex").slice(0, 16),
          status: u.approvalStatus,
          createdAt: u.createdAt,
          decidedAt: u.approvalDecidedAt,
          lastSeenAt: u.lastSeenAt,
          ...(u.rejectionReason !== null
            ? { rejectionReason: u.rejectionReason }
            : {}),
        })),
      });
    },
  );

  // --- POST /admin/users/:id/revoke ----------------------------------------
  // Move an approved user back to 'rejected' and invalidate every
  // outstanding session. Approved-but-no-longer-trusted users hit a 401
  // on their next sync poll. The admin can re-approve at any time.
  app.post<{
    Params: { id: string };
    Body: { reason?: string };
  }>(
    "/admin/users/:id/revoke",
    {
      preHandler: requireAuth,
      schema: {
        params: cast({
          type: "object",
          required: ["id"],
          properties: { id: { type: "string", pattern: "^[0-9a-f]{32}$" } },
          additionalProperties: false,
        }),
        body: cast({
          type: "object",
          properties: { reason: { type: "string", maxLength: 256 } },
          additionalProperties: false,
        }),
      },
    },
    async (req, reply) => {
      const userId = Buffer.from(req.params.id, "hex");
      const updated = deps.users.setApprovalStatus({
        userId,
        status: "rejected",
        decidedBy: req.admin!.adminId,
        ...(req.body?.reason !== undefined ? { reason: req.body.reason } : {}),
      });
      if (!updated) return reply.code(404).send({ error: "user_not_found" });
      deps.userSessions.revokeAllForUser(userId);
      deps.audit.log({
        userId,
        action: "device_revoke",
        ipHash: hmacIp(req.ip, deps.hmacKey),
        metadata: { actor: "admin", action: "revoke" },
      });
      return reply.send({ ok: true });
    },
  );

  // --- DELETE /admin/users/:id ---------------------------------------------
  // Irreversible: drops the user row. Cascades through FK to devices,
  // sessions, events, snapshots, login_attempts, and audit_log (the
  // audit row's user_id becomes NULL but the row stays for forensics).
  app.delete<{ Params: { id: string } }>(
    "/admin/users/:id",
    {
      preHandler: requireAuth,
      schema: {
        params: cast({
          type: "object",
          required: ["id"],
          properties: { id: { type: "string", pattern: "^[0-9a-f]{32}$" } },
          additionalProperties: false,
        }),
      },
    },
    async (req, reply) => {
      const userId = Buffer.from(req.params.id, "hex");
      const ok = deps.users.deleteUser(userId);
      if (!ok) return reply.code(404).send({ error: "user_not_found" });
      deps.audit.log({
        userId: null,
        action: "account_delete",
        ipHash: hmacIp(req.ip, deps.hmacKey),
        metadata: {
          actor: "admin",
          deleted_user: userId.toString("hex"),
        },
      });
      return reply.send({ ok: true });
    },
  );
}

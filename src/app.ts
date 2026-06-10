/**
 * App composition. Two surfaces can be served:
 *   - the `api` surface (user-facing auth + sync) goes on the public port,
 *   - the `admin` surface (setup + login + approval) goes on a private
 *     port (loopback by default).
 *
 * `buildServices()` opens the shared SQLite store and wires every domain
 * service. `buildApp()` then creates a Fastify instance that registers
 * only the routes for the requested mode (api / admin / both).
 *
 * Tests construct the both-modes app so they continue to work against a
 * single instance.
 */
import Fastify, { type FastifyInstance } from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import sensible from "@fastify/sensible";
import { mkdirSync } from "node:fs";
import path from "node:path";

import { createOpaqueService, type OpaqueService } from "./auth/opaque.js";
import {
  createAdminChallengeService,
  type AdminChallengeService,
} from "./auth/admin-challenges.js";
import {
  createAdminSessionService,
  type AdminSessionService,
} from "./auth/admin-sessions.js";
import {
  createChallengeService,
  type ChallengeService,
} from "./auth/challenges.js";
import {
  createLoginRateLimiter,
  type LoginRateLimiter,
} from "./auth/ratelimit.js";
import { createSessionService, type SessionService } from "./auth/sessions.js";
import type { Config } from "./config/env.js";
import { adminRoutes } from "./routes/admin.js";
import { adminUiRoutes } from "./routes/admin-ui.js";
import { authRoutes } from "./routes/auth.js";
import { healthRoutes } from "./routes/health.js";
import { syncRoutes } from "./routes/sync.js";
import { createAdminRepo, type AdminRepo } from "./store/admins.js";
import { createAuditLogger, type AuditLogger } from "./store/audit.js";
import { migrate, openStore, type Store } from "./store/db.js";
import { createSyncRepo, type SyncRepo } from "./store/sync.js";
import { createUserRepo, type UserRepo } from "./store/users.js";

export type RouteMode = "api" | "admin" | "all";

export interface Services {
  store: Store;
  opaque: OpaqueService;
  users: UserRepo;
  sessions: SessionService;
  challenges: ChallengeService;
  rateLimitLogin: LoginRateLimiter;
  audit: AuditLogger;
  sync: SyncRepo;
  admins: AdminRepo;
  adminSessions: AdminSessionService;
  adminChallenges: AdminChallengeService;
}

export interface AppOptions {
  migrationsDir?: string;
}

export async function buildServices(
  config: Config,
  options: AppOptions = {},
): Promise<Services> {
  if (config.databasePath !== ":memory:") {
    mkdirSync(path.dirname(path.resolve(config.databasePath)), {
      recursive: true,
    });
  }
  const store = openStore(config.databasePath);
  migrate(store.db, options.migrationsDir);

  const opaque = await createOpaqueService(store.db);
  return {
    store,
    opaque,
    users: createUserRepo(store.db),
    sessions: createSessionService(store.db),
    challenges: createChallengeService(store.db),
    rateLimitLogin: createLoginRateLimiter(store.db),
    audit: createAuditLogger(store.db),
    sync: createSyncRepo(store.db),
    admins: createAdminRepo(store.db),
    adminSessions: createAdminSessionService(store.db),
    adminChallenges: createAdminChallengeService(store.db),
  };
}

export async function buildApp(
  config: Config,
  options: AppOptions & { mode?: RouteMode; services?: Services } = {},
): Promise<FastifyInstance> {
  const mode: RouteMode = options.mode ?? "all";
  const services = options.services ?? (await buildServices(config, options));

  const app = Fastify({
    logger: {
      level: config.logLevel,
      redact: {
        paths: [
          "req.headers.authorization",
          "req.headers.cookie",
          "req.body",
          "res.body",
        ],
        remove: true,
      },
    },
    trustProxy: config.trustProxy,
    disableRequestLogging: false,
    bodyLimit: 2 * 1024 * 1024,
  });

  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
      },
    },
    strictTransportSecurity: {
      maxAge: 63072000,
      includeSubDomains: true,
      preload: true,
    },
    referrerPolicy: { policy: "no-referrer" },
    crossOriginResourcePolicy: { policy: "same-site" },
  });

  await app.register(sensible);

  // CORS only matters on the public API instance. The admin UI is
  // same-origin (served by the admin instance itself).
  if (mode !== "admin" && config.corsOrigins.length > 0) {
    await app.register(cors, {
      origin: [...config.corsOrigins],
      methods: ["GET", "POST", "DELETE", "OPTIONS"],
      allowedHeaders: ["Authorization", "Content-Type"],
      maxAge: 600,
      credentials: false,
    });
  }

  await app.register(rateLimit, {
    global: true,
    max: 100,
    timeWindow: "1 minute",
    keyGenerator: (req) => req.ip,
  });

  // /health is exposed on every surface so monitoring works regardless
  // of which port is reachable.
  await app.register(healthRoutes);

  if (mode === "api" || mode === "all") {
    await app.register(async (instance) => {
      await authRoutes(instance, {
        opaque: services.opaque,
        users: services.users,
        sessions: services.sessions,
        challenges: services.challenges,
        rateLimit: services.rateLimitLogin,
        audit: services.audit,
        hmacKey: config.serverHmacKey,
      });
    });
    await app.register(async (instance) => {
      await syncRoutes(instance, {
        sync: services.sync,
        sessions: services.sessions,
      });
    });
  }

  if (mode === "admin" || mode === "all") {
    await app.register(async (instance) => {
      await adminRoutes(instance, {
        opaque: services.opaque,
        admins: services.admins,
        users: services.users,
        sessions: services.adminSessions,
        userSessions: services.sessions,
        challenges: services.adminChallenges,
        audit: services.audit,
        rateLimit: services.rateLimitLogin,
        hmacKey: config.serverHmacKey,
      });
    });
    await app.register(async (instance) => {
      await adminUiRoutes(instance);
    });
  }

  app.setNotFoundHandler((_req, reply) => {
    reply.code(404).send({ error: "not_found" });
  });

  // Expose the raw DB handle for integration tests. Production paths
  // never read this property.

  (app as any).__store_db = services.store.db;

  // Each instance owns its own purge timer when the services are
  // instance-private; when shared, only the first one launched will run
  // it (the second `setInterval` is fine to coexist, the inserts are
  // idempotent).
  const purgeTimer = setInterval(() => {
    try {
      services.sessions.purgeExpired();
      services.challenges.purgeExpired();
      services.adminSessions.purgeExpired();
      services.adminChallenges.purgeExpired();
      services.rateLimitLogin.purgeOld();
    } catch (err) {
      app.log.warn({ err }, "background purge failed");
    }
  }, 60_000).unref();
  app.addHook("onClose", async () => {
    clearInterval(purgeTimer);
    // Close the shared store only on the LAST app to close. The
    // simplest convention: api closes first, admin owns the store and
    // closes it. We attach a marker via the services object — see
    // index.ts for the orchestration.
  });

  return app;
}

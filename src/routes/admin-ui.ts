/**
 * Serves the admin SPA at the admin instance's root (`/`) plus the
 * built assets at `/admin.css` and `/admin.js`. Lives only on the
 * admin Fastify instance — the public API instance doesn't register
 * this route group.
 *
 * CSP is locally relaxed for the SPA paths so the bundled JS + CSS
 * can load; the API surface still serves `default-src 'none'`.
 */
import type { FastifyInstance } from "fastify";
import fastifyStatic from "@fastify/static";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const candidates = [
  path.resolve(here, "..", "admin-ui", "static"),
  path.resolve(here, "..", "..", "src", "admin-ui", "static"),
  path.resolve(here, "..", "..", "..", "src", "admin-ui", "static"),
];

const SPA_RELAXED_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "form-action 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join("; ");

export async function adminUiRoutes(app: FastifyInstance): Promise<void> {
  const root = candidates.find((c) => existsSync(c));
  if (!root) {
    app.log.warn(
      { tried: candidates },
      "admin UI static folder not found; serving an empty stub",
    );
    app.get("/", async (_req, reply) => {
      reply
        .code(500)
        .type("text/plain")
        .send("Admin UI bundle missing. Run `npm run build:admin-ui`.");
    });
    return;
  }

  await app.register(fastifyStatic, {
    root,
    prefix: "/",
    decorateReply: false,
    cacheControl: true,
    maxAge: 60_000,
    // Defense in depth: never serve dotfiles from the static root, even if
    // a build step or operator accidentally drops one in.
    dotfiles: "deny",
    // Auto-serves index.html when the user hits "/".
    index: "index.html",
  });

  app.addHook("onSend", async (req, reply, payload) => {
    if (req.method !== "GET") return payload;
    const url = req.url.split("?")[0] ?? "";
    if (
      url === "/" ||
      url === "/index.html" ||
      url === "/admin.js" ||
      url === "/admin.css"
    ) {
      reply.header("content-security-policy", SPA_RELAXED_CSP);
    }
    return payload;
  });
}

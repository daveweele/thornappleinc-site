// Password gate for the preview site. Delete this file at launch to open the site to everyone.
// The password is read from the SITE_PASSWORD environment variable set in Netlify, never stored in the repo.
import type { Context } from "@netlify/edge-functions";

const enc = new TextEncoder();

async function sameSecret(a: string, b: string): Promise<boolean> {
  const [x, y] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const xa = new Uint8Array(x);
  const ya = new Uint8Array(y);
  let diff = 0;
  for (let i = 0; i < xa.length; i++) diff |= xa[i] ^ ya[i];
  return diff === 0;
}

export default async (request: Request, context: Context) => {
  const password = Netlify.env.get("SITE_PASSWORD");
  // Fail closed: if no password is configured, nobody gets in.
  if (!password) {
    return new Response("This site is not available yet.", { status: 503 });
  }

  const header = request.headers.get("authorization") || "";
  if (header.startsWith("Basic ")) {
    try {
      const decoded = atob(header.slice(6));
      const given = decoded.slice(decoded.indexOf(":") + 1);
      if (await sameSecret(given, password)) {
        return context.next();
      }
    } catch (_) {
      // fall through to the login prompt
    }
  }

  return new Response("Password required.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Thornapple Inc. preview", charset="UTF-8"',
      "Cache-Control": "no-store",
    },
  });
};

export const config = { path: "/*" };

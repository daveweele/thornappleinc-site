// Password gate for the preview site. Delete this file at launch to open the site to everyone.
// The password is read from the SITE_PASSWORD environment variable set in Netlify, never stored in the repo.
import type { Context } from "@netlify/edge-functions";

const COOKIE = "tp_gate";
const enc = new TextEncoder();

async function digestHex(value: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(value));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function same(a: string, b: string): Promise<boolean> {
  const [x, y] = await Promise.all([digestHex(a), digestHex(b)]);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

function loginPage(wrong: boolean): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Thornapple Inc. preview</title>
<style>
body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #12080a; color: #f4ecea; font-family: Georgia, serif; padding: 24px; }
main { width: 100%; max-width: 380px; }
h1 { font-size: 2rem; font-weight: 500; margin: 0 0 8px; }
p { color: #bfa9ab; font-family: Arial, sans-serif; line-height: 1.5; margin: 0 0 22px; }
label { display: block; font-family: Arial, sans-serif; font-size: 0.9rem; color: #bfa9ab; margin-bottom: 6px; }
input { width: 100%; box-sizing: border-box; font-size: 1.1rem; padding: 13px 14px; border-radius: 4px; border: 1px solid #3a1a21; background: #1e0d11; color: #f4ecea; }
button { margin-top: 16px; width: 100%; font-size: 1rem; font-weight: 600; padding: 13px; border-radius: 4px; border: 0; color: #fff; background: linear-gradient(135deg, #e63946, #a30d24); cursor: pointer; }
.err { color: #ff5a5f; font-family: Arial, sans-serif; margin: 0 0 14px; }
</style>
</head>
<body>
<main>
<h1>Thornapple Inc.</h1>
<p>This site is in preview. Enter the password to continue.</p>
${wrong ? '<p class="err">That password is not right. Try again.</p>' : ""}
<form method="POST" action="/_login">
<label for="pw">Password</label>
<input id="pw" name="password" type="password" autocomplete="current-password" autofocus required>
<button type="submit">Enter</button>
</form>
</main>
</body>
</html>`;
  return new Response(html, {
    status: 401,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

export default async (request: Request, context: Context) => {
  const password = Netlify.env.get("SITE_PASSWORD");
  // Fail closed: if no password is configured, nobody gets in.
  if (!password) {
    return new Response("This site is not available yet.", { status: 503 });
  }

  const expected = await digestHex("thornapple-gate:" + password);

  // Already signed in?
  const cookies = request.headers.get("cookie") || "";
  const mine = cookies.split(/;\s*/).find((c) => c.startsWith(COOKIE + "="));
  if (mine && (await same(mine.slice(COOKIE.length + 1), expected))) {
    return context.next();
  }

  // Password submitted?
  const url = new URL(request.url);
  if (request.method === "POST" && url.pathname === "/_login") {
    let given = "";
    try {
      const form = await request.formData();
      given = String(form.get("password") || "");
    } catch (_) {
      // treat as wrong password
    }
    if (given && (await same(given, password))) {
      return new Response(null, {
        status: 303,
        headers: {
          Location: "/",
          "Set-Cookie": `${COOKIE}=${expected}; Max-Age=2592000; Path=/; HttpOnly; Secure; SameSite=Lax`,
          "Cache-Control": "no-store",
        },
      });
    }
    return loginPage(true);
  }

  return loginPage(false);
};

export const config = { path: "/*" };

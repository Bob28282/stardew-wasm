// Gates the whole site behind a simple password screen.
// A correct password sets an HttpOnly cookie so the visitor only has to enter it once.

const COOKIE_NAME = "site_access";
const LOGIN_PATH = "/__unlock";

async function sha256(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getPassword(): string {
  return Netlify.env.get("SITE_PASSWORD") || "avalon";
}

async function expectedToken(): Promise<string> {
  return sha256(`site-gate:v1:${getPassword()}`);
}

function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.get("cookie") || "";
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return undefined;
}

function safeRedirectTarget(value: string | null): string {
  if (!value || !value.startsWith("/") || value.startsWith("//")) return "/";
  return value;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!
  );
}

function loginPage(next: string, error: boolean): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="robots" content="noindex" />
<title>Enter password</title>
<link rel="icon" href="data:," />
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; background: #fff; color: #111; font-family: system-ui, -apple-system, sans-serif; }
  body { display: flex; align-items: center; justify-content: center; }
  form { display: flex; flex-direction: column; gap: 0.75rem; width: min(320px, 90vw); }
  input {
    font: inherit; font-size: 1rem; padding: 0.7rem 0.9rem;
    border: 1px solid #ccc; border-radius: 6px; outline: none;
  }
  input:focus { border-color: #111; }
  button {
    font: inherit; font-size: 1rem; padding: 0.7rem; border: none; border-radius: 6px;
    background: #111; color: #fff; cursor: pointer;
  }
  button:hover { background: #333; }
  .error { color: #c00; font-size: 0.9rem; }
</style>
</head>
<body>
  <form method="POST" action="${LOGIN_PATH}">
    <input type="hidden" name="next" value="${escapeHtml(next)}" />
    <input type="password" name="password" placeholder="Password" aria-label="Password" autofocus required />
    ${error ? '<p class="error">Incorrect password.</p>' : ""}
    <button type="submit">Enter</button>
  </form>
</body>
</html>`;
  return new Response(html, {
    status: error ? 401 : 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

export default async (req: Request) => {
  const url = new URL(req.url);
  const token = await expectedToken();

  if (url.pathname === LOGIN_PATH && req.method === "POST") {
    const form = await req.formData().catch(() => null);
    const password = String(form?.get("password") ?? "");
    const next = safeRedirectTarget(String(form?.get("next") ?? "/"));
    if (password === getPassword()) {
      return new Response(null, {
        status: 303,
        headers: {
          location: next,
          "set-cookie": `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`,
          "cache-control": "no-store",
        },
      });
    }
    return loginPage(next, true);
  }

  if (readCookie(req, COOKIE_NAME) === token) {
    if (url.pathname === LOGIN_PATH) {
      return Response.redirect(new URL("/", url), 303);
    }
    return; // authorized — continue to the site
  }

  return loginPage(url.pathname + url.search, false);
};

export const config = {
  path: "/*",
};

// Basic Auth middleware for Fulfillment Portal
// Credentials: fulfillment / slate2026fulfill

const VALID_CREDENTIALS = [
  "admin:slate2026admin",
  "fulfillment:slate2026fulfill"
];

const REALM = "Slate Systems Fulfillment Portal";

function parseBasicAuth(request) {
  const authorization = request.headers.get("Authorization");
  if (!authorization) return null;

  const [scheme, encoded] = authorization.split(" ");
  if (scheme !== "Basic") return null;

  const decoded = atob(encoded);
  const [username, password] = decoded.split(":");
  return { username, password };
}

function unauthorized() {
  return new Response("Unauthorized", {
    status: 401,
    headers: {
      "WWW-Authenticate": `Basic realm="${REALM}", charset="UTF-8"`,
    },
  });
}

export async function onRequest(context) {
  const credentials = parseBasicAuth(context.request);

  if (!credentials) {
    return unauthorized();
  }

  const { username, password } = credentials;
  const validCredential = `${username}:${password}`;

  if (!VALID_CREDENTIALS.includes(validCredential)) {
    return unauthorized();
  }

  return context.next();
}

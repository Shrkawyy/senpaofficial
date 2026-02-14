import crypto from "crypto";

function verifyToken(token, secret) {
  const [data, sig] = (token || "").split(".");
  if (!data || !sig) return null;

  const expected = crypto.createHmac("sha256", secret)
    .update(data)
    .digest("base64url");

  if (expected !== sig) return null;

  let payload;
  try {
    payload = JSON.parse(
      Buffer.from(data, "base64url").toString("utf8")
    );
  } catch {
    return null;
  }

  if (!payload.exp || Date.now() > payload.exp) return null;

  return payload;
}

export default async function handler(req, res) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

  const payload = verifyToken(token, process.env.LICENSE_SECRET);
  if (!payload) return res.status(401).json({ ok: false });

  return res.status(200).json({ ok: true });
}

import crypto from "crypto";

function signToken(payload, secret) {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(data).digest("base64url");
  return `${data}.${sig}`;
}

async function kvGet(key) {
  const url = `${process.env.KV_REST_API_URL}/get/${encodeURIComponent(key)}`;
  const r = await fetch(url, {
    headers: { Authorization: `Bearer ${process.env.KV_REST_API_TOKEN}` },
  });
  const j = await r.json();
  return j?.result ?? null;
}

async function kvSet(key, value) {
  const url = `${process.env.KV_REST_API_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(value)}`;
  const r = await fetch(url, {
    headers: { Authorization: `Bearer ${process.env.KV_REST_API_TOKEN}` },
  });
  return r.ok;
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ ok: false });

  const { key } = req.body || {};
  if (!key || typeof key !== "string" || key.trim().length < 6) {
    return res.status(400).json({ ok: false, error: "KEY_INVALID" });
  }

  const cleanKey = key.trim();
  const dbKey = `license:${cleanKey}`;

  const raw = await kvGet(dbKey);
  if (!raw) return res.status(401).json({ ok: false, error: "KEY_NOT_FOUND" });

  let info;
  try { info = JSON.parse(raw); } catch { info = null; }
  if (!info) return res.status(500).json({ ok: false, error: "KEY_DATA_BROKEN" });

  if (info.used) {
    return res.status(403).json({ ok: false, error: "KEY_ALREADY_USED" });
  }

  info.used = true;
  info.usedAt = Date.now();

  await kvSet(dbKey, JSON.stringify(info));

  const token = signToken(
    { k: cleanKey, exp: Date.now() + 60 * 60 * 1000 },
    process.env.LICENSE_SECRET
  );

  return res.status(200).json({ ok: true, token });
}

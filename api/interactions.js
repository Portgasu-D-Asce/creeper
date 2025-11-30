import { verifyKey } from "discord-interactions";

export const config = {
  api: {
    bodyParser: false, // IMPORTANT: Required for Discord signature validation
  },
};

export default async function handler(req, res) {
  const PUBLIC_KEY = process.env.DISCORD_PUBLIC_KEY;

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const signature = req.headers["x-signature-ed25519"];
  const timestamp = req.headers["x-signature-timestamp"];

  // Read raw body (critical)
  const rawBody = await getRawBody(req);

  // Validate signature
  let valid = false;
  try {
    valid = verifyKey(rawBody, signature, timestamp, PUBLIC_KEY);
  } catch (err) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  if (!valid) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  const body = JSON.parse(rawBody.toString());

  // PING -> required for Discord endpoint verification
  if (body.type === 1) {
    return res.status(200).json({ type: 1 });
  }

  return res.status(200).json({
    type: 4,
    data: { content: "Creeper bot online!" }
  });
}

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = Buffer.from([]);
    req.on("data", (chunk) => {
      data = Buffer.concat([data, chunk]);
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

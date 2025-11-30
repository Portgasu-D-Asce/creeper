import fetch from "node-fetch";
import nacl from "tweetnacl";

const PUBLIC_KEY = process.env.DISCORD_PUBLIC_KEY;
const PEBBLE_API_KEY = process.env.PEBBLE_API_KEY;
const PEBBLE_SERVER_ID = process.env.PEBBLE_SERVER_ID;
const MINECRAFT_ROLE_ID = process.env.MINECRAFT_ROLE_ID;

// Read raw body
function getRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

// Verify Discord signature
function verifySig(body, sig, ts) {
  const msg = new TextEncoder().encode(ts + body);
  const sigBin = Buffer.from(sig, "hex");
  const pubBin = Buffer.from(PUBLIC_KEY, "hex");
  return nacl.sign.detached.verify(msg, sigBin, pubBin);
}

export default async (req, res) => {
  const signature = req.headers["x-signature-ed25519"];
  const timestamp = req.headers["x-signature-timestamp"];
  const rawBody = await getRawBody(req);

  if (!verifySig(rawBody, signature, timestamp)) {
    return res.status(401).send("invalid signature");
  }

  const data = JSON.parse(rawBody);

  // PING from Discord
  if (data.type === 1) {
    return res.json({ type: 1 });
  }

  // Slash commands
  if (data.type === 2) {
    const cmd = data.data.name;
    const roles = data.member.roles || [];

    if (cmd === "start_srv") {
      if (!roles.includes(MINECRAFT_ROLE_ID)) {
        return res.json({
          type: 4,
          data: {
            content: "You do not have permission to start the server.",
            flags: 64
          }
        });
      }

      // Call Pebble API
      await fetch(
        `https://api.pebblehost.com/api/client/servers/${PEBBLE_SERVER_ID}/power`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${PEBBLE_API_KEY}`
          },
          body: JSON.stringify({ signal: "start" })
        }
      );

      return res.json({
        type: 4,
        data: {
          content: "Server start request sent! Give it a minute.",
          flags: 64
        }
      });
    }

    // Unknown command fallback
    return res.json({
      type: 4,
      data: { content: "Unknown command.", flags: 64 }
    });
  }

  res.json({ type: 4, data: { content: "Unhandled event.", flags: 64 } });
};

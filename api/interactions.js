import nacl from "tweetnacl";

// Helper: get raw body for signature verification
async function getRawBody(req) {
  return await new Promise((resolve, reject) => {
    let data = "";

    req.on("data", (chunk) => {
      data += chunk;
    });

    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

// Helper: verify Discord signature
function verifyDiscordSignature(rawBody, signature, timestamp, clientPublicKey) {
  const body = new TextEncoder().encode(rawBody);
  const sig = Buffer.from(signature, "hex");
  const time = Buffer.from(timestamp, "utf8");
  const pubKey = Buffer.from(clientPublicKey, "hex");

  return nacl.sign.detached.verify(
    Buffer.concat([time, body]),
    sig,
    pubKey
  );
}

export default async function handler(req, res) {
  const PUBLIC_KEY = process.env.DISCORD_PUBLIC_KEY;

  const signature = req.headers["x-signature-ed25519"];
  const timestamp = req.headers["x-signature-timestamp"];
  const rawBody = await getRawBody(req);

  if (
    !verifyDiscordSignature(
      rawBody,
      signature,
      timestamp,
      PUBLIC_KEY
    )
  ) {
    return res.status(401).send("invalid request signature");
  }

  // Handle "ping" from Discord → must reply type 1
  const body = JSON.parse(rawBody);

  if (body.type === 1) {
    return res.status(200).json({ type: 1 });
  }

  // You can handle your slash commands later
  return res.status(200).json({
    type: 4,
    data: { content: "Bot online!" }
  });
}

export const config = {
  api: {
    bodyParser: false,
  },
};

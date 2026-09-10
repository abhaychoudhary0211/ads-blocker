const dnsPacket = require("dns-packet");

const UPSTREAM_DOH =
  process.env.UPSTREAM_DOH ||
  "https://cloudflare-dns.com/dns-query";

const BLOCKED = new Set([
  "ads.example.com",
  "tracker.example.com",
  "doubleclick.net"
]);

function isBlocked(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, "");

  if (BLOCKED.has(host)) {
    return true;
  }

  const parts = host.split(".");

  for (let i = 1; i < parts.length - 1; i++) {
    if (BLOCKED.has(parts.slice(i).join("."))) {
      return true;
    }
  }

  return false;
}

function createBlockedResponse(request) {
  const answers = [];

  for (const question of request.questions || []) {
    if (question.type === "A") {
      answers.push({
        name: question.name,
        type: "A",
        class: "IN",
        ttl: 60,
        data: "0.0.0.0"
      });
    }

    if (question.type === "AAAA") {
      answers.push({
        name: question.name,
        type: "AAAA",
        class: "IN",
        ttl: 60,
        data: "::"
      });
    }
  }

  return dnsPacket.encode({
    type: "response",
    id: request.id,
    flags:
      dnsPacket.RECURSION_DESIRED |
      dnsPacket.RECURSION_AVAILABLE,
    questions: request.questions || [],
    answers,
    authorities: [],
    additionals: []
  });
}

function decodeGetRequest(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    normalized +
    "=".repeat((4 - (normalized.length % 4)) % 4);

  return Buffer.from(padded, "base64");
}

module.exports = async function handler(req, res) {
  try {
    if (req.method !== "GET" && req.method !== "POST") {
      res.setHeader("Allow", "GET, POST");
      return res.status(405).send("Method Not Allowed");
    }

    let dnsMessage;

    if (req.method === "GET") {
      const url = new URL(req.url, "https://localhost");
      const dns = url.searchParams.get("dns");

      if (!dns) {
        return res.status(400).send("Missing dns parameter");
      }

      dnsMessage = decodeGetRequest(dns);
    } else {
      dnsMessage = Buffer.isBuffer(req.body)
        ? req.body
        : Buffer.from(req.body || "");
    }

    const dnsRequest = dnsPacket.decode(dnsMessage);
    const question = dnsRequest.questions?.[0];

    if (!question?.name) {
      return res.status(400).send("Missing DNS question");
    }

    if (isBlocked(question.name)) {
      const response = createBlockedResponse(dnsRequest);

      res.setHeader("Content-Type", "application/dns-message");
      res.setHeader("Cache-Control", "public, max-age=60");

      return res.status(200).send(response);
    }

    const upstream = await fetch(UPSTREAM_DOH, {
      method: "POST",
      headers: {
        "content-type": "application/dns-message",
        accept: "application/dns-message"
      },
      body: dnsMessage
    });

    if (!upstream.ok) {
      return res.status(502).send("Upstream DNS error");
    }

    const responseBuffer = Buffer.from(
      await upstream.arrayBuffer()
    );

    res.setHeader("Content-Type", "application/dns-message");
    res.setHeader("Cache-Control", "no-store");

    return res.status(200).send(responseBuffer);
  } catch (error) {
    console.error(error);
    return res.status(500).send("DNS processing error");
  }
};

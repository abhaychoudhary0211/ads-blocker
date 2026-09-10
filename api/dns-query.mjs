import dnsPacket from "dns-packet";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const UPSTREAM_DOH =
  process.env.UPSTREAM_DOH ||
  "https://cloudflare-dns.com/dns-query";

const BLOCKLIST_PATH = path.join(__dirname, "blocklist.txt");

let blockedDomains;

function loadBlocklist() {
  if (blockedDomains) {
    return blockedDomains;
  }

  const text = fs.readFileSync(BLOCKLIST_PATH, "utf8");

  blockedDomains = new Set(
    text
      .split(/\r?\n/)
      .map(domain => domain.trim().toLowerCase())
      .filter(Boolean)
  );

  console.log(
    `Loaded ${blockedDomains.size} blocked domains`
  );

  return blockedDomains;
}

function isBlocked(hostname) {
  const blocklist = loadBlocklist();

  const host = hostname
    .toLowerCase()
    .replace(/\.$/, "");

  if (blocklist.has(host)) {
    return true;
  }

  const parts = host.split(".");

  for (let i = 1; i < parts.length - 1; i++) {
    if (blocklist.has(parts.slice(i).join("."))) {
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

async function processDns(request) {
  let dnsMessage;

  if (request.method === "GET") {
    const url = new URL(request.url);
    const dns = url.searchParams.get("dns");

    if (!dns) {
      return new Response("Missing dns parameter", {
        status: 400
      });
    }

    dnsMessage = decodeGetRequest(dns);
  } else if (request.method === "POST") {
    dnsMessage = Buffer.from(await request.arrayBuffer());
  } else {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: {
        Allow: "GET, POST"
      }
    });
  }

  const dnsRequest = dnsPacket.decode(dnsMessage);
  const question = dnsRequest.questions?.[0];

  if (!question?.name) {
    return new Response("Missing DNS question", {
      status: 400
    });
  }

  if (isBlocked(question.name)) {
    console.log("BLOCKED:", question.name);

    return new Response(
      createBlockedResponse(dnsRequest),
      {
        status: 200,
        headers: {
          "Content-Type": "application/dns-message",
          "Cache-Control": "public, max-age=60"
        }
      }
    );
  }

  console.log("FORWARDED:", question.name);

  const upstream = await fetch(UPSTREAM_DOH, {
    method: "POST",
    headers: {
      "Content-Type": "application/dns-message",
      Accept: "application/dns-message"
    },
    body: dnsMessage
  });

  if (!upstream.ok) {
    return new Response("Upstream DNS error", {
      status: 502
    });
  }

  const responseBody = await upstream.arrayBuffer();

  return new Response(responseBody, {
    status: 200,
    headers: {
      "Content-Type": "application/dns-message",
      "Cache-Control": "no-store"
    }
  });
}

export async function GET(request) {
  try {
    return await processDns(request);
  } catch (error) {
    console.error("DNS GET error:", error);

    return new Response("DNS processing error", {
      status: 500
    });
  }
}

export async function POST(request) {
  try {
    return await processDns(request);
  } catch (error) {
    console.error("DNS POST error:", error);

    return new Response("DNS processing error", {
      status: 500
    });
  }
}

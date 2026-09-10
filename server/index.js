const Fastify = require('fastify');
const cors = require('@fastify/cors');
const dnsPacket = require('dns-packet');
const fs = require('fs');
const path = require('path');

const app = Fastify({ logger: true });

const PORT = Number(process.env.PORT || 3000);
const UPSTREAM_DOH =
  process.env.UPSTREAM_DOH || 'https://cloudflare-dns.com/dns-query';

const BLOCKLIST_FILE = path.join(__dirname, 'blocklist.txt');

let stats = {
  total: 0,
  blocked: 0,
  forwarded: 0
};

function loadBlocklist() {
  if (!fs.existsSync(BLOCKLIST_FILE)) {
    return new Set();
  }

  return new Set(
    fs.readFileSync(BLOCKLIST_FILE, 'utf8')
      .split(/\r?\n/)
      .map(line => line.trim().toLowerCase())
      .filter(line => line && !line.startsWith('#'))
      .map(line => line
        .replace(/^0\.0\.0\.0\s+/, '')
        .replace(/^127\.0\.0\.1\s+/, '')
        .replace(/^\*\./, '')
        .replace(/\.$/, '')
      )
  );
}

let blocklist = loadBlocklist();

function isBlocked(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, '');

  if (blocklist.has(host)) {
    return true;
  }

  const parts = host.split('.');

  for (let i = 1; i < parts.length - 1; i++) {
    const parent = parts.slice(i).join('.');

    if (blocklist.has(parent)) {
      return true;
    }
  }

  return false;
}

function createBlockedResponse(request) {
  const answers = [];

  for (const question of request.questions || []) {
    if (question.type === 'A') {
      answers.push({
        name: question.name,
        type: 'A',
        class: 'IN',
        ttl: 60,
        data: '0.0.0.0'
      });
    }

    if (question.type === 'AAAA') {
      answers.push({
        name: question.name,
        type: 'AAAA',
        class: 'IN',
        ttl: 60,
        data: '::'
      });
    }
  }

  return dnsPacket.encode({
    type: 'response',
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

async function handleDnsMessage(buffer, reply) {
  let request;

  try {
    request = dnsPacket.decode(buffer);
  } catch {
    return reply.code(400).send('Invalid DNS message');
  }

  const question = request.questions?.[0];

  if (!question?.name) {
    return reply.code(400).send('Missing DNS question');
  }

  const hostname = question.name;
  stats.total++;

  app.log.info({
    hostname,
    type: question.type
  }, 'DNS request');

  if (isBlocked(hostname)) {
    stats.blocked++;

    app.log.info({ hostname }, 'BLOCKED');

    const body = createBlockedResponse(request);

    return reply
      .header('content-type', 'application/dns-message')
      .header('cache-control', 'no-store')
      .send(body);
  }

  stats.forwarded++;

  app.log.info({ hostname }, 'FORWARDED');

  try {
    const upstreamResponse = await fetch(UPSTREAM_DOH, {
      method: 'POST',
      headers: {
        'content-type': 'application/dns-message',
        accept: 'application/dns-message'
      },
      body: buffer
    });

    if (!upstreamResponse.ok) {
      return reply.code(502).send('Upstream DNS error');
    }

    const responseBuffer = Buffer.from(
      await upstreamResponse.arrayBuffer()
    );

    return reply
      .header('content-type', 'application/dns-message')
      .header('cache-control', 'no-store')
      .send(responseBuffer);
  } catch (error) {
    request.log.error(error, 'Upstream DNS request failed');
    return reply.code(502).send('Upstream DNS unavailable');
  }
}

app.register(cors, {
  origin: true
});

app.addContentTypeParser(
  'application/dns-message',
  { parseAs: 'buffer' },
  (request, body, done) => {
    done(null, body);
  }
);

app.get('/', async () => ({
  name: 'My AdBlocker',
  status: 'online',
  blockedDomains: blocklist.size
}));

app.get('/health', async () => ({
  status: 'ok'
}));

app.get('/stats', async () => ({
  total: stats.total,
  blocked: stats.blocked,
  forwarded: stats.forwarded,
  blockRate: stats.total
    ? Number(((stats.blocked / stats.total) * 100).toFixed(2))
    : 0,
  blockedDomains: blocklist.size
}));

app.post('/reload', async () => {
  blocklist = loadBlocklist();

  return {
    status: 'reloaded',
    blockedDomains: blocklist.size
  };
});

app.get('/dns-query', async (request, reply) => {
  try {
    const encoded = request.query?.dns;

    if (!encoded) {
      return reply.code(400).send('Missing dns query parameter');
    }

    const normalized = encoded
      .replace(/-/g, '+')
      .replace(/_/g, '/');

    const padded =
      normalized +
      '='.repeat((4 - (normalized.length % 4)) % 4);

    const dnsMessage = Buffer.from(padded, 'base64');

    return await handleDnsMessage(dnsMessage, reply);
  } catch (error) {
    request.log.error(error);
    return reply.code(500).send('DNS processing error');
  }
});

app.post('/dns-query', async (request, reply) => {
  try {
    const body = Buffer.isBuffer(request.body)
      ? request.body
      : Buffer.from(request.body || '');

    return await handleDnsMessage(body, reply);
  } catch (error) {
    request.log.error(error);
    return reply.code(500).send('DNS processing error');
  }
});

app.listen({
  port: PORT,
  host: '0.0.0.0'
})
  .then(() => {
    app.log.info(`My AdBlocker listening on port ${PORT}`);
  })
  .catch(error => {
    app.log.error(error);
    process.exit(1);
  });

const dnsPacket = require("dns-packet");

async function test(domain) {
  const request = dnsPacket.encode({
    type: "query",
    id: 1234,
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [
      {
        type: "A",
        name: domain
      }
    ]
  });

  const response = await fetch(
    "https://ads-blocker.vercel.app/dns-query",
    {
      method: "POST",
      headers: {
        "content-type": "application/dns-message"
      },
      body: request
    }
  );

  console.log("\nDOMAIN:", domain);
  console.log("HTTP:", response.status);

  const buffer = Buffer.from(await response.arrayBuffer());
  const result = dnsPacket.decode(buffer);

  console.log("RCODE:", result.rcode);
  console.log("ANSWERS:", result.answers);
}

(async () => {
  await test("ads.example.com");
  await test("google.com");
})();

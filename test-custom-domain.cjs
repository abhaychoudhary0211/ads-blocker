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
    "https://ad-blocker.iamabhay0211.site/dns-query",
    {
      method: "POST",
      headers: {
        "content-type": "application/dns-message"
      },
      body: request
    }
  );

  const buffer = Buffer.from(await response.arrayBuffer());

  console.log("\nDOMAIN:", domain);
  console.log("HTTP:", response.status);

  if (!response.ok) {
    console.log("BODY:", buffer.toString());
    return;
  }

  const result = dnsPacket.decode(buffer);

  console.log("RCODE:", result.rcode);
  console.log("ANSWERS:", result.answers);
}

(async () => {
  await test("0-ilxrc-w285.p9bckp.sbs");
  await test("google.com");
})();

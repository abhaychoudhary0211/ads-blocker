const fs = require("fs");
const https = require("https");
const path = require("path");

const URL =
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";

const OUTPUT = path.join(__dirname, "..", "api", "blocklist.txt");

https.get(URL, (response) => {
  if (response.statusCode !== 200) {
    console.error("Failed to download blocklist:", response.statusCode);
    process.exit(1);
  }

  let data = "";

  response.setEncoding("utf8");

  response.on("data", chunk => {
    data += chunk;
  });

  response.on("end", () => {
    const domains = new Set();

    for (const line of data.split(/\r?\n/)) {
      const trimmed = line.trim();

      if (!trimmed || trimmed.startsWith("#")) continue;

      const parts = trimmed.split(/\s+/);

      if (parts.length < 2) continue;

      const ip = parts[0];

      if (ip !== "0.0.0.0" && ip !== "127.0.0.1") continue;

      for (const domain of parts.slice(1)) {
        if (
          domain &&
          !domain.includes("/") &&
          domain.includes(".")
        ) {
          domains.add(
            domain.toLowerCase().replace(/\.$/, "")
          );
        }
      }
    }

    const sorted = [...domains].sort();

    fs.writeFileSync(
      OUTPUT,
      sorted.join("\n") + "\n"
    );

    console.log(
      `Saved ${sorted.length} domains to ${OUTPUT}`
    );
  });
}).on("error", error => {
  console.error("Download failed:", error);
  process.exit(1);
});

import { LegacyGlobalWriteQuarantinedError } from "../services/governance/legacyWriteQuarantine.js";

async function main() {
  throw new LegacyGlobalWriteQuarantinedError("npm run seed:generic");
}

main()
  .catch((error) => {
    console.error("Failed to initialize generic example", error);
    process.exitCode = 1;
  });

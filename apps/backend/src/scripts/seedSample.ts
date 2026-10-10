import { LegacyGlobalWriteQuarantinedError } from "../services/governance/legacyWriteQuarantine.js";

async function main() {
  throw new LegacyGlobalWriteQuarantinedError("npm run seed:sample");
}

main()
  .catch((error) => {
    console.error("Failed to initialize sample data", error);
    process.exitCode = 1;
  });

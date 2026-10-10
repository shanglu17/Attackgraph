import { LegacyGlobalWriteQuarantinedError } from "../services/governance/legacyWriteQuarantine.js";

/** Retained command name; global deletion is quarantined after P1.6. */
async function main() {
  throw new LegacyGlobalWriteQuarantinedError("npm run clear");
}

main()
  .catch((error) => {
    console.error("Failed to clear graph", error);
    process.exitCode = 1;
  });

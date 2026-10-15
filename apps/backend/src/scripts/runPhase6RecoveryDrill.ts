import { closeDriver } from "../db/neo4j.js";
import { runRecoveryDrill } from "../services/operations/recoveryDrillService.js";

try {
  console.log(JSON.stringify(await runRecoveryDrill("phase6"), null, 2));
} finally {
  await closeDriver();
}

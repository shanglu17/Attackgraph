import { closeDriver } from "../db/neo4j.js";
import { GraphRepository } from "../repositories/graphRepository.js";

async function main() {
  const repo = new GraphRepository();
  await repo.ensureConstraints();
  const result = await repo.seedGenericExample("cli-generic-seed");
  console.log("Generic example initialized", result);
}

main()
  .catch((error) => {
    console.error("Failed to initialize generic example", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await closeDriver();
  });

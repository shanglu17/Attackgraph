import { closeDriver } from "../db/neo4j.js";
import { GraphRepository } from "../repositories/graphRepository.js";

async function main() {
  const repo = new GraphRepository();
  await repo.ensureConstraints();
  const result = await repo.seedSampleData("cli-seed");
  console.log("Sample data initialized", result);
}

main()
  .catch((error) => {
    console.error("Failed to initialize sample data", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await closeDriver();
  });

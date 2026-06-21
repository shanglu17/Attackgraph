import { closeDriver, getDriver } from "../db/neo4j.js";

/** Wipe every node + relationship from Neo4j. Run via `npm run clear`. */
async function main() {
  const session = getDriver().session();
  try {
    const result = await session.run("MATCH (n) DETACH DELETE n");
    const c = result.summary.counters.updates();
    console.log(`Graph cleared — ${c.nodesDeleted} nodes, ${c.relationshipsDeleted} relationships deleted.`);
  } finally {
    await session.close();
  }
}

main()
  .catch((error) => {
    console.error("Failed to clear graph", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await closeDriver();
  });

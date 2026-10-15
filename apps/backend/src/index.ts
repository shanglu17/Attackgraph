import { env } from "./config/env.js";
import { closeDriver } from "./db/neo4j.js";
import { GraphRepository } from "./repositories/graphRepository.js";
import { StandardRepository } from "./repositories/standardRepository.js";
import { createApp } from "./app.js";

const app = createApp();
const graphRepo = new GraphRepository();
const standardRepo = new StandardRepository();

const start = async () => {
  await Promise.all([graphRepo.ensureConstraints(), standardRepo.ensureConstraints()]);
  app.listen(env.port, () => {
    console.log(`Backend API listening on http://localhost:${env.port}`);
  });
};

start().catch((error) => {
  console.error("Failed to start backend", error);
  process.exit(1);
});

process.on("SIGINT", async () => {
  await closeDriver();
  process.exit(0);
});

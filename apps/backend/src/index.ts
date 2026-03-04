import cors from "cors";
import express from "express";
import { env } from "./config/env.js";
import { closeDriver } from "./db/neo4j.js";
import { GraphRepository } from "./repositories/graphRepository.js";
import router from "./routes/index.js";

const app = express();
const graphRepo = new GraphRepository();

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(router);

app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const message = error instanceof Error ? error.message : "未知错误";
  res.status(500).json({ message });
});

const start = async () => {
  await graphRepo.ensureConstraints();
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

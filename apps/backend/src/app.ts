import cors from "cors";
import express from "express";
import router from "./routes/index.js";
import operationsRouter from "./routes/operations.js";
import { observeRequests } from "./operations/requestMetrics.js";

export function createApp(options: { log?: (entry: Record<string, unknown>) => void } = {}) {
  const app = express();
  app.disable("x-powered-by");
  app.use(cors());
  app.use(observeRequests(options.log));
  app.use(express.json({ limit: "50mb" }));
  app.use("/api/v2/operations", operationsRouter);
  app.use(router);
  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const message = error instanceof Error ? error.message : "未知错误";
    const statusCode = typeof error === "object" && error !== null && "statusCode" in error ? Number(error.statusCode) : 500;
    res.status(Number.isInteger(statusCode) && statusCode >= 400 && statusCode < 600 ? statusCode : 500).json({ message });
  });
  return app;
}

import path from "node:path";
import { closeDriver } from "../db/neo4j.js";
import { StandardRepository } from "../repositories/standardRepository.js";
import { F3532StandardModelService } from "../services/f3532StandardModelService.js";

const defaultCsvDir = "E:\\document\\airness\\standardClause\\f3532_model\\csv";

const csvDir = process.argv[2] ? path.resolve(process.argv[2]) : defaultCsvDir;
const loader = new F3532StandardModelService();
const repo = new StandardRepository();

try {
  const payload = await loader.loadCsvDirectory(csvDir);
  const summary = await repo.importF3532KnowledgeBase({
    ...payload,
    source: {
      ...payload.source,
      imported_by: "f3532-standard-script"
    }
  });
  console.log(JSON.stringify({ imported: true, summary }, null, 2));
} finally {
  await closeDriver();
}

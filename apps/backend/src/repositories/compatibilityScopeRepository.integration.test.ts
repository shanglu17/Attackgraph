import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, describe, it } from "node:test";
import { closeDriver, getDriver } from "../db/neo4j.js";
import {
  CompatibilityScopeInputError,
  CompatibilityScopeNotFoundError,
  CompatibilityScopeRepository,
} from "./compatibilityScopeRepository.js";

const repository = new CompatibilityScopeRepository();
const runId = randomUUID();
const projectId = randomUUID();
const modelId = randomUUID();
const revisionId = randomUUID();

after(async () => {
  const session = getDriver().session();
  try {
    await session.run(
      `MATCH (node {p16_test_run: $run_id}) DETACH DELETE node`,
      { run_id: runId },
    );
  } finally {
    await session.close();
    await closeDriver();
  }
});

describe("CompatibilityScopeRepository", () => {
  it("accepts only an existing project/revision pair and never infers a partial scope", async () => {
    const session = getDriver().session();
    try {
      await session.run(
        `CREATE (project:Project {
           id: $project_id, business_id: $project_business_id, name: 'P1.6 scope test',
           p16_test_run: $run_id
         })
         CREATE (model:Model {
           id: $model_id, project_id: $project_id, business_id: 'MODEL-001',
           p16_test_run: $run_id
         })
         CREATE (revision:Revision {
           id: $revision_id, project_id: $project_id, model_id: $model_id,
           business_id: 'REV-001', status: 'Draft', version: 1,
           p16_test_run: $run_id
         })
         CREATE (project)-[:HAS_MODEL]->(model)-[:HAS_REVISION]->(revision)`,
        {
          run_id: runId,
          project_id: projectId,
          project_business_id: `P16-${runId}`,
          model_id: modelId,
          revision_id: revisionId,
        },
      );
    } finally {
      await session.close();
    }

    const resolved = await repository.resolve({
      project_id: projectId,
      revision_id: revisionId,
    });
    assert.deepEqual(resolved, {
      project_id: projectId,
      model_id: modelId,
      revision_id: revisionId,
      source: "explicit",
    });

    await assert.rejects(repository.resolve({ project_id: projectId }), CompatibilityScopeInputError);
    await assert.rejects(
      repository.resolve({ project_id: projectId, revision_id: randomUUID() }),
      CompatibilityScopeNotFoundError,
    );
  });
});

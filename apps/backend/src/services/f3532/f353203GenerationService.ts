import type { F353203GenerationFacts, F353203GenerationResult } from "../../types/domain.js";
import { BoundaryFlowReportService } from "./boundaryFlowReportService.js";
import { BusinessPathRuleEngine } from "./businessPathRuleEngine.js";
import { PropagationGraphBuilder } from "./propagationGraphBuilder.js";
import { F353203ReportAssembler } from "./reportAssembler.js";

export class F353203GenerationService {
  private readonly boundaryFlowReport = new BoundaryFlowReportService();
  private readonly graphBuilder = new PropagationGraphBuilder();
  private readonly ruleEngine = new BusinessPathRuleEngine();
  private readonly assembler = new F353203ReportAssembler();

  generate(
    facts: F353203GenerationFacts,
    options: { max_hops?: number; mode?: "preview" | "commit" | "loaded" } = {}
  ): F353203GenerationResult {
    const boundaryRows = this.boundaryFlowReport.build(facts);
    const graph = this.graphBuilder.build(facts);
    const paths = this.ruleEngine.generate(facts, graph, options.max_hops ?? 8);
    const rows = this.assembler.assemblePathRows(paths, facts.trust_boundaries);
    return {
      metadata: {
        generated_at: new Date().toISOString(),
        graph_version: facts.graph_version,
        mode: options.mode ?? "preview",
        generator_version: "f3532-03-deterministic-v2",
        confirmed_count: paths.filter((path) => path.status === "CONFIRMED").length,
        needs_review_count: paths.filter((path) => path.status === "NEEDS_REVIEW").length,
        unmatched_count: paths.filter((path) => path.status === "UNMATCHED").length,
        warnings: facts.warnings
      },
      boundary_data_flows: { count: boundaryRows.length, rows: boundaryRows },
      propagation_paths: { count: rows.length, rows, paths }
    };
  }
}

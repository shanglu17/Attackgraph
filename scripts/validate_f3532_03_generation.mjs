import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

import { F353203GenerationService } from "../apps/backend/src/services/f3532/f353203GenerationService.ts";
import { normalizeF3532WorkbookFacts } from "../apps/backend/src/services/f3532/factNormalizer.ts";

const DEFAULT_OUTPUT = "artifacts/f3532-03-generation-validation.json";

function usage() {
  return [
    "Usage:",
    "  CODEX_NODE_MODULES=<workspace-deps-node_modules> npx tsx scripts/validate_f3532_03_generation.mjs [file01] [file02] [file03] [output.json]",
    "",
    "If file paths are omitted, the script scans ~/Desktop for 01*.xlsx, 02*.xlsx and 03*.xlsx."
  ].join("\n");
}

async function loadArtifactTool() {
  const nodeModules = process.env.CODEX_NODE_MODULES ?? process.env.ARTIFACT_TOOL_NODE_MODULES;
  if (!nodeModules) {
    throw new Error(`Missing CODEX_NODE_MODULES. ${usage()}`);
  }
  const require = createRequire(path.join(nodeModules, "package.json"));
  const modulePath = require.resolve("@oai/artifact-tool");
  return import(pathToFileURL(modulePath).href);
}

async function findDesktopWorkbook(prefix) {
  const desktop = path.join(os.homedir(), "Desktop");
  const files = await fs.readdir(desktop);
  const matches = files
    .filter((name) => name.startsWith(prefix) && name.toLowerCase().endsWith(".xlsx") && !name.startsWith("~$"))
    .sort((left, right) => left.localeCompare(right, undefined, { numeric: true }));
  if (matches.length === 0) {
    throw new Error(`Could not find ${prefix}*.xlsx on Desktop.`);
  }
  return path.join(desktop, matches[0]);
}

async function readWorkbook(filePath) {
  const { FileBlob, SpreadsheetFile } = await loadArtifactTool();
  const blob = await FileBlob.load(filePath);
  return SpreadsheetFile.importXlsx(blob);
}

function cell(row, index) {
  const value = row?.[index];
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text.length > 0 ? text : undefined;
}

function dataRows(matrix) {
  return matrix.slice(1).filter((row) => row.some((value) => String(value ?? "").trim().length > 0));
}

function getSheetMatrix(workbook, index) {
  const sheet = workbook.worksheets.getItemAt(index);
  return sheet.getUsedRange(true).values ?? [];
}

function parseInput01(workbook) {
  const boundaryInterfaces = dataRows(getSheetMatrix(workbook, 0)).map((row, index) => ({
    id: required(row, 0, "01 boundary_interfaces", index + 2),
    interface_class: cell(row, 1),
    external_entity: cell(row, 2),
    access_object: cell(row, 3),
    access_device: cell(row, 4),
    physical_interconnect: cell(row, 5),
    logical_protocol: cell(row, 6),
    direction: cell(row, 7),
    description: cell(row, 8),
    notes: cell(row, 9),
    excel_row: index + 2
  }));

  const bdfMatrix = getSheetMatrix(workbook, 1);
  const bdfHeaderWidth = (bdfMatrix[0] ?? []).filter((value) => String(value ?? "").trim().length > 0).length;
  const isCurrentBdfLayout = bdfHeaderWidth >= 10;
  const boundaryDataFlows = dataRows(bdfMatrix).map((row, index) => ({
    id: required(row, 0, "01 boundary_data_flows", index + 2),
    producer: cell(row, 1),
    consumer: cell(row, 2),
    destination: cell(row, 3),
    description: cell(row, 4),
    data_flow_type: cell(row, 5),
    target_function: cell(row, 6),
    failure_condition: isCurrentBdfLayout ? cell(row, 7) : undefined,
    notes: isCurrentBdfLayout ? cell(row, 8) : cell(row, 7),
    boundary_interface_id: isCurrentBdfLayout ? cell(row, 9) : cell(row, 8),
    excel_row: index + 2
  }));

  const systemInterfaces = dataRows(getSheetMatrix(workbook, 2)).map((row, index) => ({
    id: required(row, 0, "01 system_interfaces", index + 2),
    producer: cell(row, 1),
    consumer: cell(row, 2),
    interface_type: cell(row, 3),
    protocol: cell(row, 4),
    direction: cell(row, 5),
    content: cell(row, 6),
    notes: cell(row, 7),
    excel_row: index + 2
  }));

  const systemDataFlows = dataRows(getSheetMatrix(workbook, 3)).map((row, index) => ({
    id: required(row, 0, "01 system_data_flows", index + 2),
    producer: cell(row, 1),
    consumer: cell(row, 2),
    destination: cell(row, 3),
    content: cell(row, 4),
    data_flow_type: cell(row, 5),
    target_function: cell(row, 6),
    failure_condition: cell(row, 7),
    notes: cell(row, 8),
    system_interface_id: cell(row, 9),
    excel_row: index + 2
  }));

  return { boundaryInterfaces, boundaryDataFlows, systemInterfaces, systemDataFlows };
}

function parseInput02(workbook) {
  const threatActors = dataRows(getSheetMatrix(workbook, 0)).map((row, index) => ({
    id: required(row, 0, "02 threat_actors", index + 2),
    name: cell(row, 1),
    actor_type: cell(row, 2),
    description: cell(row, 3),
    excel_row: index + 2
  }));

  const trustBoundaries = dataRows(getSheetMatrix(workbook, 1)).map((row, index) => ({
    boundary_id: required(row, 0, "02 trust_boundaries", index + 2),
    name: cell(row, 1),
    description: cell(row, 2),
    covered_scope: cell(row, 3),
    threat_actor_refs: cell(row, 4),
    excel_row: index + 2
  }));

  return { threatActors, trustBoundaries };
}

function parseStandard03(workbook) {
  const boundaryRows = dataRows(getSheetMatrix(workbook, 0)).map((row, index) => ({
    row: index + 2,
    security_boundary_text: cell(row, 0) ?? "",
    security_boundary_ids: extractIds(cell(row, 0), "SB"),
    data_flow_type: (cell(row, 1) ?? "").toUpperCase(),
    boundary_interface_ids: extractIds(cell(row, 2), "BI"),
    bdf_ids: extractIds(cell(row, 3), "BDF"),
    function_ids: extractFunctionIds(cell(row, 4))
  }));

  const pathRows = dataRows(getSheetMatrix(workbook, 1)).map((row, index) => ({
    row: index + 2,
    path_id: normalizePathId(cell(row, 0) ?? `STANDARD_ROW_${index + 2}`),
    path_name: cell(row, 1) ?? "",
    data_flow_types: extractDataTypes(cell(row, 2)),
    origin: cell(row, 3) ?? "",
    boundary_interface_ids: extractIds(cell(row, 4), "BI"),
    sdf_ids: extractIds(cell(row, 5), "SDF"),
    system_interface_ids: extractIds(cell(row, 6), "SI"),
    bdf_ids: extractIds(cell(row, 7), "BDF"),
    function_ids: extractFunctionIds(cell(row, 8)),
    path_description: cell(row, 9) ?? ""
  }));

  return { boundaryRows, pathRows };
}

function required(row, index, scope, excelRow) {
  const value = cell(row, index);
  if (!value) throw new Error(`${scope} row ${excelRow}: required column ${index + 1} is empty.`);
  return value;
}

function normalizePathId(raw) {
  const match = String(raw).match(/P\s*0*(\d+)/i);
  return match ? `P${String(Number(match[1])).padStart(2, "0")}` : String(raw).trim();
}

function normalizeBusinessId(prefix, value) {
  const upperPrefix = prefix.toUpperCase();
  const numeric = Number(value);
  if (upperPrefix === "BI" || upperPrefix === "SB") {
    return `${upperPrefix}${String(numeric).padStart(2, "0")}`;
  }
  return `${upperPrefix}${numeric}`;
}

function extractIds(raw, prefix) {
  if (!raw) return [];
  const text = String(raw).toUpperCase();
  const ids = new Set();
  const rangePattern = new RegExp(`${prefix}\\s*[-_]?\\s*0*(\\d+)\\s*(?:~|-|TO|至|到)\\s*(?:${prefix}\\s*[-_]?\\s*)?0*(\\d+)`, "gi");
  for (const match of text.matchAll(rangePattern)) {
    const start = Number(match[1]);
    const end = Number(match[2]);
    const step = start <= end ? 1 : -1;
    for (let value = start; step > 0 ? value <= end : value >= end; value += step) {
      ids.add(normalizeBusinessId(prefix, value));
    }
  }
  const singlePattern = new RegExp(`${prefix}\\s*[-_]?\\s*0*(\\d+)`, "gi");
  for (const match of text.matchAll(singlePattern)) {
    ids.add(normalizeBusinessId(prefix, match[1]));
  }
  return sortBusinessIds([...ids]);
}

function extractFunctionIds(raw) {
  if (!raw) return [];
  return sortBusinessIds([...new Set([...String(raw).matchAll(/F\s*0*(\d+(?:\.\d+)*)/gi)].map((match) => `F${match[1]}`))]);
}

function extractDataTypes(raw) {
  if (!raw) return [];
  return sortBusinessIds(
    String(raw)
      .split(/[\/、,，;；\s]+/)
      .map((value) => value.trim().toUpperCase())
      .filter(Boolean)
  );
}

function normalizeSet(values, prefix) {
  if (!Array.isArray(values)) return [];
  if (prefix === "F") return sortBusinessIds(values.map((value) => String(value).replace(/\s+/g, "").toUpperCase()));
  return sortBusinessIds(values.flatMap((value) => extractIds(String(value), prefix)));
}

function sortBusinessIds(values) {
  return [...new Set(values.filter(Boolean))].sort((left, right) =>
    left.localeCompare(right, undefined, { numeric: true, sensitivity: "base" })
  );
}

function setDiff(left, right) {
  const rightSet = new Set(right);
  return left.filter((item) => !rightSet.has(item));
}

function sameSet(left, right) {
  return left.length === right.length && setDiff(left, right).length === 0;
}

function jaccard(left, right) {
  const a = new Set(left);
  const b = new Set(right);
  const union = new Set([...a, ...b]);
  if (union.size === 0) return 1;
  let intersection = 0;
  for (const item of a) {
    if (b.has(item)) intersection += 1;
  }
  return intersection / union.size;
}

function compareFirstSheet(generatedRows, standardRows) {
  const expectedByBdf = new Map();
  for (const row of standardRows) {
    for (const bdfId of row.bdf_ids) {
      expectedByBdf.set(bdfId, row);
    }
  }

  const generatedByBdf = new Map(
    generatedRows.map((row) => [
      normalizeSet([row.bdf_id], "BDF")[0] ?? row.bdf_id,
      {
        security_boundary_ids: normalizeSet(row.security_boundary_ids, "SB"),
        data_flow_type: String(row.data_flow_type ?? "").toUpperCase(),
        boundary_interface_ids: normalizeSet(row.boundary_interface_ids, "BI"),
        bdf_id: normalizeSet([row.bdf_id], "BDF")[0] ?? row.bdf_id,
        function_ids: normalizeSet(row.function_ids, "F"),
        direction: row.direction,
        warnings: row.warnings ?? []
      }
    ])
  );

  const missingBdfs = setDiff([...expectedByBdf.keys()], [...generatedByBdf.keys()]);
  const extraBdfs = setDiff([...generatedByBdf.keys()], [...expectedByBdf.keys()]);
  const mismatches = [];
  let matched = 0;
  for (const [bdfId, expected] of expectedByBdf.entries()) {
    const actual = generatedByBdf.get(bdfId);
    if (!actual) continue;
    const issues = [];
    if (!sameSet(expected.security_boundary_ids, actual.security_boundary_ids)) {
      issues.push({ field: "SB", expected: expected.security_boundary_ids, actual: actual.security_boundary_ids });
    }
    if (!sameSet(expected.boundary_interface_ids, actual.boundary_interface_ids)) {
      issues.push({ field: "BI", expected: expected.boundary_interface_ids, actual: actual.boundary_interface_ids });
    }
    if (expected.data_flow_type !== actual.data_flow_type) {
      issues.push({ field: "data_flow_type", expected: expected.data_flow_type, actual: actual.data_flow_type });
    }
    if (!sameSet(expected.function_ids, actual.function_ids)) {
      issues.push({ field: "function", expected: expected.function_ids, actual: actual.function_ids });
    }
    if (issues.length === 0) matched += 1;
    else mismatches.push({ bdf_id: bdfId, issues, actual_warnings: actual.warnings });
  }

  return {
    standard_count: standardRows.length,
    generated_count: generatedRows.length,
    expected_bdf_count: expectedByBdf.size,
    generated_bdf_count: generatedByBdf.size,
    matched_bdf_count: matched,
    mismatched_bdf_count: mismatches.length,
    missing_bdf_count: missingBdfs.length,
    extra_bdf_count: extraBdfs.length,
    missing_bdfs: missingBdfs,
    extra_bdfs: extraBdfs,
    mismatches
  };
}

function normalizeGeneratedPathRow(row) {
  return {
    path_id: normalizePathId(row.path_id),
    status: row.status,
    rule_id: row.rule_id,
    boundary_interface_ids: normalizeSet(row.boundary_interface_ids, "BI"),
    system_interface_ids: normalizeSet(row.system_interface_ids, "SI"),
    bdf_ids: normalizeSet(row.bdf_ids, "BDF"),
    sdf_ids: normalizeSet(row.sdf_ids, "SDF"),
    function_ids: normalizeSet(row.function_ids, "F"),
    data_flow_types: extractDataTypes((row.data_flow_types ?? []).join("/")),
    system_path: row.system_path ?? "",
    route_segment_sdf_ids: normalizeSet((row.route_segments ?? []).flatMap((segment) => segment.sdf_ids ?? []), "SDF"),
    warnings: row.warnings ?? []
  };
}

function compareSecondSheet(generatedRows, standardRows) {
  const generated = generatedRows.map(normalizeGeneratedPathRow);
  const unused = new Set(generated.map((_, index) => index));
  const matches = [];
  for (const expected of standardRows) {
    let bestIndex = -1;
    let bestScore = -1;
    for (const index of unused) {
      const actual = generated[index];
      const idBonus = actual.path_id === expected.path_id ? 0.2 : 0;
      const score =
        idBonus +
        jaccard(expected.bdf_ids, actual.bdf_ids) * 0.38 +
        jaccard(expected.sdf_ids, actual.sdf_ids) * 0.38 +
        jaccard(expected.boundary_interface_ids, actual.boundary_interface_ids) * 0.08 +
        jaccard(expected.system_interface_ids, actual.system_interface_ids) * 0.08 +
        jaccard(expected.function_ids, actual.function_ids) * 0.08;
      if (score > bestScore) {
        bestScore = score;
        bestIndex = index;
      }
    }
    if (bestIndex >= 0) unused.delete(bestIndex);
    const actual = bestIndex >= 0 ? generated[bestIndex] : undefined;
    matches.push(buildPathDiff(expected, actual, bestScore));
  }

  const exactMemberMatches = matches.filter((item) => item.member_exact).length;
  const extraGenerated = [...unused].map((index) => generated[index]);
  const segmentConsistencyProblems = generated
    .map((row) => ({
      path_id: row.path_id,
      missing_sdf_ids_in_route_segments: setDiff(row.sdf_ids, row.route_segment_sdf_ids)
    }))
    .filter((item) => item.missing_sdf_ids_in_route_segments.length > 0);

  return {
    standard_count: standardRows.length,
    generated_count: generatedRows.length,
    exact_member_match_count: exactMemberMatches,
    partial_or_mismatch_count: matches.length - exactMemberMatches,
    extra_generated_count: extraGenerated.length,
    needs_review_count: generated.filter((row) => row.status === "NEEDS_REVIEW").length,
    unmatched_count: generated.filter((row) => row.status === "UNMATCHED").length,
    segment_consistency_problem_count: segmentConsistencyProblems.length,
    matches,
    extra_generated: extraGenerated,
    segment_consistency_problems: segmentConsistencyProblems
  };
}

function buildPathDiff(expected, actual, score) {
  if (!actual) {
    return {
      standard_path_id: expected.path_id,
      generated_path_id: null,
      score,
      member_exact: false,
      missing_all: true
    };
  }
  const diffs = {
    missing_bdf: setDiff(expected.bdf_ids, actual.bdf_ids),
    extra_bdf: setDiff(actual.bdf_ids, expected.bdf_ids),
    missing_sdf: setDiff(expected.sdf_ids, actual.sdf_ids),
    extra_sdf: setDiff(actual.sdf_ids, expected.sdf_ids),
    missing_bi: setDiff(expected.boundary_interface_ids, actual.boundary_interface_ids),
    extra_bi: setDiff(actual.boundary_interface_ids, expected.boundary_interface_ids),
    missing_si: setDiff(expected.system_interface_ids, actual.system_interface_ids),
    extra_si: setDiff(actual.system_interface_ids, expected.system_interface_ids),
    missing_function: setDiff(expected.function_ids, actual.function_ids),
    extra_function: setDiff(actual.function_ids, expected.function_ids),
    missing_data_type: setDiff(expected.data_flow_types, actual.data_flow_types),
    extra_data_type: setDiff(actual.data_flow_types, expected.data_flow_types)
  };
  const memberExact =
    diffs.missing_bdf.length === 0 &&
    diffs.extra_bdf.length === 0 &&
    diffs.missing_sdf.length === 0 &&
    diffs.extra_sdf.length === 0 &&
    diffs.missing_bi.length === 0 &&
    diffs.extra_bi.length === 0 &&
    diffs.missing_si.length === 0 &&
    diffs.extra_si.length === 0 &&
    diffs.missing_function.length === 0 &&
    diffs.extra_function.length === 0 &&
    diffs.missing_data_type.length === 0 &&
    diffs.extra_data_type.length === 0;

  return {
    standard_path_id: expected.path_id,
    generated_path_id: actual.path_id,
    generated_status: actual.status,
    generated_rule_id: actual.rule_id,
    score: Number(score.toFixed(4)),
    member_exact: memberExact,
    standard_description: expected.path_description,
    generated_system_path: actual.system_path,
    diffs,
    generated_warnings: actual.warnings
  };
}

async function main() {
  const [file01Arg, file02Arg, file03Arg, outputArg] = process.argv.slice(2);
  const file01 = file01Arg ? path.resolve(file01Arg) : await findDesktopWorkbook("01");
  const file02 = file02Arg ? path.resolve(file02Arg) : await findDesktopWorkbook("02");
  const file03 = file03Arg ? path.resolve(file03Arg) : await findDesktopWorkbook("03");
  const output = outputArg ? path.resolve(outputArg) : path.resolve(DEFAULT_OUTPUT);

  const [workbook01, workbook02, workbook03] = await Promise.all([
    readWorkbook(file01),
    readWorkbook(file02),
    readWorkbook(file03)
  ]);
  const parsed01 = parseInput01(workbook01);
  const parsed02 = parseInput02(workbook02);
  const inputPayload = {
    template_version: "f3532_input_01_02_v1",
    source: {
      aircraft_model: "F3532-ASTRA",
      file_names: [path.basename(file01), path.basename(file02)],
      submitted_by: "validation-script",
      submitted_at: new Date().toISOString()
    },
    workbook: {
      boundary_interfaces: parsed01.boundaryInterfaces,
      boundary_data_flows: parsed01.boundaryDataFlows,
      system_interfaces: parsed01.systemInterfaces,
      system_data_flows: parsed01.systemDataFlows,
      threat_actors: parsed02.threatActors,
      trust_boundaries: parsed02.trustBoundaries
    }
  };

  const facts = normalizeF3532WorkbookFacts(inputPayload.workbook, "golden-file-in-memory");
  const generated = new F353203GenerationService().generate(facts, { mode: "preview", max_hops: 8 });
  const standard = parseStandard03(workbook03);
  const firstSheet = compareFirstSheet(generated.boundary_data_flows.rows, standard.boundaryRows);
  const secondSheet = compareSecondSheet(generated.propagation_paths.rows, standard.pathRows);

  const report = {
    generated_at: new Date().toISOString(),
    inputs: {
      file01,
      file02,
      file03,
      counts: {
        boundary_interfaces: parsed01.boundaryInterfaces.length,
        boundary_data_flows: parsed01.boundaryDataFlows.length,
        system_interfaces: parsed01.systemInterfaces.length,
        system_data_flows: parsed01.systemDataFlows.length,
        threat_actors: parsed02.threatActors.length,
        trust_boundaries: parsed02.trustBoundaries.length
      }
    },
    generated_metadata: generated.metadata,
    first_sheet: firstSheet,
    second_sheet: secondSheet
  };

  await fs.mkdir(path.dirname(output), { recursive: true });
  await fs.writeFile(output, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  console.log(
    JSON.stringify(
      {
        output,
        input_counts: report.inputs.counts,
        generated_metadata: generated.metadata,
        first_sheet: {
          standard_count: firstSheet.standard_count,
          generated_count: firstSheet.generated_count,
          matched_bdf_count: firstSheet.matched_bdf_count,
          mismatched_bdf_count: firstSheet.mismatched_bdf_count,
          missing_bdf_count: firstSheet.missing_bdf_count,
          extra_bdf_count: firstSheet.extra_bdf_count
        },
        second_sheet: {
          standard_count: secondSheet.standard_count,
          generated_count: secondSheet.generated_count,
          exact_member_match_count: secondSheet.exact_member_match_count,
          partial_or_mismatch_count: secondSheet.partial_or_mismatch_count,
          extra_generated_count: secondSheet.extra_generated_count,
          needs_review_count: secondSheet.needs_review_count,
          unmatched_count: secondSheet.unmatched_count,
          segment_consistency_problem_count: secondSheet.segment_consistency_problem_count
        }
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});

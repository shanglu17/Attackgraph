import assert from "node:assert/strict";
import { test } from "node:test";
import * as XLSX from "xlsx";
import { parseF3532Workbooks } from "../src/f3532Workbook";

test("both file reads start without waiting for the other file", async () => {
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([["invalid"]]), "invalid");
  const bytes = XLSX.write(wb, { type: "array", bookType: "xlsx" });
  let release!: () => void;
  let secondStarted = false;
  const first = new File([bytes], "01.xlsx");
  const second = new File([bytes], "02.xlsx");
  first.arrayBuffer = () => new Promise(resolve => { release = () => resolve(bytes); });
  second.arrayBuffer = async () => { secondStarted = true; return bytes; };
  const result = parseF3532Workbooks(first, second, "test").catch(error => error);
  // Dynamic import may take a turn; wait for the first read to begin.
  while (!release) await new Promise(resolve => setTimeout(resolve, 5));
  const concurrent = secondStarted;
  release();
  const error = await result;
  assert.equal(error.kind, "file");
  assert.match(error.message, /Missing required sheet/);
  assert.equal(concurrent, true, "02 must begin reading while 01 is still pending");
});

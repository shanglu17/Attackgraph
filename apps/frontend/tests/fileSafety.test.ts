import assert from "node:assert/strict";
import test from "node:test";
import { assertSafeLocalFile } from "../src/fileSafety.js";

test("local import guard rejects unexpected, empty and oversized files", () => {
  assert.doesNotThrow(() => assertSafeLocalFile({ name: "model.xlsx", size: 1024 }, [".xlsx"], 15));
  assert.throws(() => assertSafeLocalFile({ name: "model.xlsm", size: 1024 }, [".xlsx"], 15), /不支持/);
  assert.throws(() => assertSafeLocalFile({ name: "model.xlsx", size: 0 }, [".xlsx"], 15), /为空/);
  assert.throws(() => assertSafeLocalFile({ name: "model.xlsx", size: 16 * 1024 * 1024 }, [".xlsx"], 15), /过大/);
});

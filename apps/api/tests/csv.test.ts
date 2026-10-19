import { it, expect } from "vitest";
import { csvCell } from "../src/explorer.js";
it("neutralizes CSV formulas including whitespace prefixes and quotes values", () => {
  for (const value of ["=1+1", "+SUM(A1)", "-1+2", "@test", " \t=1"])
    expect(csvCell(value).startsWith("\"'")).toBe(true);
  expect(csvCell('hello,"world"')).toBe('"hello,""world"""');
  expect(csvCell(null)).toBe('""');
});

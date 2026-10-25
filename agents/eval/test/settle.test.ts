// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

// node:fs with cpSync and rmSync that a test can make fail: a copy that fails partway, and a partial copy
// that can't be removed, are hard to make happen for real
vi.mock("node:fs", async (importOriginal) => {
  const real = await importOriginal<typeof import("node:fs")>();
  return { ...real, cpSync: vi.fn(real.cpSync), rmSync: vi.fn(real.rmSync) };
});
const fs = await import("node:fs");
const realFs = await vi.importActual<typeof import("node:fs")>("node:fs");
const { settleWorkspace } = await import("../src/runner.ts");

const tmp = realFs.mkdtempSync(join(tmpdir(), "paztport-settle-"));
afterAll(() => realFs.rmSync(tmp, { recursive: true, force: true }));
afterEach(() => vi.mocked(fs.cpSync).mockReset().mockImplementation(realFs.cpSync));
afterEach(() => vi.mocked(fs.rmSync).mockReset().mockImplementation(realFs.rmSync));

let n = 0;
function setup(): { work: string; runDir: string; stderr: string } {
  const runDir = join(tmp, `run-${n}`);
  const work = join(tmp, `work-${n++}`);
  realFs.mkdirSync(join(work, "website"), { recursive: true });
  realFs.writeFileSync(join(work, "website/leak.md"), "private text");
  realFs.mkdirSync(runDir);
  const stderr = join(runDir, "stderr.txt");
  realFs.writeFileSync(stderr, "");
  return { work, runDir, stderr };
}

describe("settleWorkspace", () => {
  it("copies the working folder in as workspace/ and removes it", () => {
    const { work, runDir, stderr } = setup();
    settleWorkspace(work, join(runDir, "workspace"), stderr);
    expect(realFs.readFileSync(join(runDir, "workspace/website/leak.md"), "utf8")).toBe("private text");
    expect(realFs.existsSync(work)).toBe(false);
    expect(realFs.existsSync(join(runDir, ".workspace-copy"))).toBe(false);
    expect(realFs.readFileSync(stderr, "utf8")).toBe("");
  });

  it("a copy that fails partway, and can't be removed, is never at workspace/ where the scorer reads", () => {
    const { work, runDir, stderr } = setup();
    let failed = false;
    vi.mocked(fs.cpSync).mockImplementation((_src, dest) => {
      // part of the folder arrives, then the copy fails
      realFs.mkdirSync(join(String(dest), "website"), { recursive: true });
      realFs.writeFileSync(join(String(dest), "website/leak.md"), "private text");
      failed = true;
      throw Object.assign(new Error("copy failed"), { code: "EIO" });
    });
    vi.mocked(fs.rmSync).mockImplementation((path, opts) => {
      if (failed && String(path).startsWith(runDir)) throw Object.assign(new Error("rm failed"), { code: "EACCES" });
      realFs.rmSync(path, opts);
    });
    settleWorkspace(work, join(runDir, "workspace"), stderr);
    expect(realFs.existsSync(join(runDir, "workspace"))).toBe(false);
    const text = realFs.readFileSync(stderr, "utf8");
    expect(text).toContain("runner: could not copy the workspace into the run folder (EIO), so it is left out\n");
    expect(text).toContain("runner: and its partial copy, .workspace-copy, could not be removed; it is never scored\n");
    expect(text).not.toContain(work);
    // the partial copy is under its other name, which scoring never reads
    expect(realFs.existsSync(join(runDir, ".workspace-copy/website/leak.md"))).toBe(true);
    // the working folder still goes
    expect(realFs.existsSync(work)).toBe(false);
  });
});

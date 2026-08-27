import { describe, expect, it } from "vitest";
import { NodeProcessHost } from "./process-manager";

describe("executor process host", () => {
  it("passes metacharacters as one literal argument without a shell", async () => {
    const host = new NodeProcessHost();
    const payload = "hello; $(whoami) && echo unsafe";
    const running = host.start({
      executable: process.execPath,
      args: ["-e", "process.stdout.write(JSON.stringify(process.argv.slice(1)))", payload],
    });

    await expect(running.completion).resolves.toMatchObject({
      exitCode: 0,
      stdout: JSON.stringify([payload]),
      stderr: "",
    });
  });

  it("returns an explicit spawn error for an unavailable executable", async () => {
    const host = new NodeProcessHost();
    await expect(host.probe({
      executable: "catomicals-command-that-does-not-exist",
      args: ["--version"],
    })).resolves.toMatchObject({ exitCode: null, error: "ENOENT" });
  });
});

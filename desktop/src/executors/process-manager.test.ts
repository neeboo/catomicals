import { describe, expect, it } from "vitest";
import { NodeProcessHost } from "./process-manager";

describe("executor process host", () => {
  it("passes metacharacters as one literal argument without a shell", async () => {
    const host = new NodeProcessHost();
    const payload = "hello; $(whoami) && echo unsafe";
    const running = host.start({
      executable: process.execPath,
      args: ["-e", "process.stdout.write(JSON.stringify(process.argv.slice(1)))", payload],
      environmentKeys: [],
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
      environmentKeys: [],
    })).resolves.toMatchObject({ exitCode: null, error: "ENOENT" });
  });

  it("terminates a process that exceeds the bounded output contract", async () => {
    const host = new NodeProcessHost();
    const running = host.start({
      executable: process.execPath,
      args: ["-e", 'process.stdout.write("x".repeat(1_100_000)); setInterval(() => {}, 1_000)'],
      environmentKeys: [],
    });

    const result = await Promise.race([
      running.completion,
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 1_500)),
    ]);
    if (result === null) await host.dispose();

    expect(result).toMatchObject({ error: "output-limit" });
  });

  it("forces shutdown after a child ignores the graceful interrupt", async () => {
    const host = new NodeProcessHost();
    host.start({
      executable: process.execPath,
      args: ["-e", 'process.on("SIGTERM", () => {}); setTimeout(() => process.exit(0), 2_000); setInterval(() => {}, 1_000)'],
      environmentKeys: [],
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    const startedAt = Date.now();

    await host.dispose();

    expect(Date.now() - startedAt).toBeLessThan(1_000);
  });

  it("passes only explicitly allowlisted host environment values", async () => {
    const host = new NodeProcessHost();
    process.env.CATOMICALS_TEST_ALLOWED = "allowed";
    process.env.CATOMICALS_TEST_SECRET = "secret";
    try {
      const running = host.start({
        executable: process.execPath,
        args: ["-e", 'process.stdout.write(JSON.stringify({allowed:process.env.CATOMICALS_TEST_ALLOWED,secret:process.env.CATOMICALS_TEST_SECRET}))'],
        environmentKeys: ["CATOMICALS_TEST_ALLOWED"],
      });

      await expect(running.completion).resolves.toMatchObject({
        exitCode: 0,
        stdout: JSON.stringify({ allowed: "allowed" }),
      });
    } finally {
      delete process.env.CATOMICALS_TEST_ALLOWED;
      delete process.env.CATOMICALS_TEST_SECRET;
    }
  });

  it("adds only the two per-launch Cordis values without mutating process.env", async () => {
    const host = new NodeProcessHost();
    delete process.env.CATOMICALS_CORDIS_BRIDGE_URL;
    delete process.env.CATOMICALS_CORDIS_SESSION_TOKEN;
    const running = host.start({
      executable: process.execPath,
      args: ["-e", [
        "process.stdout.write(JSON.stringify({",
        "url:process.env.CATOMICALS_CORDIS_BRIDGE_URL,",
        "token:process.env.CATOMICALS_CORDIS_SESSION_TOKEN",
        "}))",
      ].join("")],
      environmentKeys: [],
    }, {
      CATOMICALS_CORDIS_BRIDGE_URL: "http://127.0.0.1:49152",
      CATOMICALS_CORDIS_SESSION_TOKEN: "session-secret",
    });

    await expect(running.completion).resolves.toMatchObject({
      exitCode: 0,
      stdout: JSON.stringify({
        url: "http://127.0.0.1:49152",
        token: "session-secret",
      }),
    });
    expect(process.env.CATOMICALS_CORDIS_BRIDGE_URL).toBeUndefined();
    expect(process.env.CATOMICALS_CORDIS_SESSION_TOKEN).toBeUndefined();
  });

  it("rejects every per-launch environment key outside the Cordis pair", () => {
    const host = new NodeProcessHost();
    expect(() => host.start({
      executable: process.execPath,
      args: ["-e", ""],
      environmentKeys: [],
    }, { OTHER_SECRET: "no" } as never)).toThrow("invalid executor environment override");
  });
});

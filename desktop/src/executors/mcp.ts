import { mkdtemp, rmdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CordisAgentSessionCredential } from "../cordis/agent-bridge.js";
import type { ExecutorCommand, ExecutorMcpConfiguration, ExecutorProviderId } from "./types.js";
import { executorEnvironmentKeys } from "./types.js";
import type { ExecutorEnvironmentOverrides } from "./process-manager.js";

const CORDIS_BRIDGE_URL = "CATOMICALS_CORDIS_BRIDGE_URL";
const CORDIS_SESSION_TOKEN = "CATOMICALS_CORDIS_SESSION_TOKEN";

export interface ExecutorMcpSessionAssembly {
  readonly configuration: ExecutorMcpConfiguration;
  readonly environment: ExecutorEnvironmentOverrides;
  dispose(): Promise<void>;
}

function assertCordisMcpCommand(command: string): void {
  if (command.trim() === "" || command.length > 4096 || /[\0\r\n]/.test(command)) {
    throw new Error("invalid Cordis MCP command");
  }
}

function assertCredential(credential: CordisAgentSessionCredential): void {
  let endpoint: URL;
  try {
    endpoint = new URL(credential.endpoint);
  } catch {
    throw new Error("invalid Cordis MCP credential");
  }
  if (endpoint.protocol !== "http:" || endpoint.hostname !== "127.0.0.1"
    || endpoint.port === "" || endpoint.username !== "" || endpoint.password !== ""
    || endpoint.pathname !== "/" || endpoint.search !== "" || endpoint.hash !== "") {
    throw new Error("invalid Cordis MCP credential");
  }
  const port = Number(endpoint.port);
  if (!Number.isSafeInteger(port) || port <= 0 || port > 65_535
    || !/^[A-Za-z0-9_-]{1,512}$/.test(credential.token)) {
    throw new Error("invalid Cordis MCP credential");
  }
}

function deepseekPatch(command: string): string {
  return [
    "- insert:",
    "    - id: catomicals-cordis-mcp",
    "      name: '@deepseek-ai/dsh-mcp-client'",
    "      config:",
    "        serverName: catomicals",
    "        transport: stdio",
    `        command: ${JSON.stringify(command)}`,
    "        args: ['mcp', 'cordis-serve']",
    "        env:",
    `          ${CORDIS_BRIDGE_URL}: !!js process.env.${CORDIS_BRIDGE_URL}`,
    `          ${CORDIS_SESSION_TOKEN}: !!js process.env.${CORDIS_SESSION_TOKEN}`,
    "        cwd: !!js process.cwd()",
    "        failOnStartupError: true",
    "        reconnect:",
    "          enabled: false",
    "",
  ].join("\n");
}

async function createDeepseekPatch(command: string): Promise<{ path: string; dispose(): Promise<void> }> {
  const directory = await mkdtemp(join(tmpdir(), "catomicals-cordis-"));
  const path = join(directory, "cordis.patch.yml");
  try {
    await writeFile(path, deepseekPatch(command), { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch (error) {
    await rmdir(directory).catch(() => undefined);
    throw error;
  }
  let disposed = false;
  return {
    path,
    async dispose() {
      if (disposed) return;
      disposed = true;
      await unlink(path).catch((error: NodeJS.ErrnoException) => {
        if (error.code !== "ENOENT") throw error;
      });
      await rmdir(directory).catch((error: NodeJS.ErrnoException) => {
        if (error.code !== "ENOENT") throw error;
      });
    },
  };
}

export function buildCordisMcpCapabilityProbe(command: string): ExecutorCommand {
  assertCordisMcpCommand(command);
  return {
    executable: command,
    args: ["mcp", "cordis-serve", "--help"],
    environmentKeys: executorEnvironmentKeys([]),
  };
}

export async function prepareExecutorMcpSession(
  provider: ExecutorProviderId,
  credential: CordisAgentSessionCredential,
  command: string,
): Promise<ExecutorMcpSessionAssembly> {
  assertCordisMcpCommand(command);
  assertCredential(credential);
  let patch: Awaited<ReturnType<typeof createDeepseekPatch>> | undefined;
  if (provider === "deepseek") patch = await createDeepseekPatch(command);
  return {
    configuration: {
      command,
      ...(patch ? { deepseekPatchPath: patch.path } : {}),
    },
    environment: Object.freeze({
      CATOMICALS_CORDIS_BRIDGE_URL: credential.endpoint,
      CATOMICALS_CORDIS_SESSION_TOKEN: credential.token,
    }),
    dispose: () => patch?.dispose() ?? Promise.resolve(),
  };
}

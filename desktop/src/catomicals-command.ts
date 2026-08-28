import { existsSync } from "node:fs";
import { join } from "node:path";

export function resolveCatomicalsCommand(
  projectRoot: string,
  exists: (path: string) => boolean = existsSync,
  platform: NodeJS.Platform = process.platform,
): string {
  const executable = platform === "win32" ? "catomicals.exe" : "catomicals";
  const workspaceCommand = join(projectRoot, "target", "debug", executable);
  return exists(workspaceCommand) ? workspaceCommand : executable;
}

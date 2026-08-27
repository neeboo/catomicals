import type { CordisSettings } from "./settings.js";

export interface CordisMigration {
  readonly from: number;
  readonly to: number;
  readonly migrate: (settings: CordisSettings) => CordisSettings;
}

export function runMigrations(
  settings: CordisSettings,
  current: number,
  target: number,
  migrations: readonly CordisMigration[],
): CordisSettings {
  if (!Number.isSafeInteger(current) || !Number.isSafeInteger(target) || current < 0 || target < current) {
    throw new Error("invalid migration range");
  }
  let version = current;
  let candidate = structuredClone(settings);
  const bySource = new Map<number, CordisMigration>();
  for (const migration of migrations) {
    if (migration.to !== migration.from + 1 || bySource.has(migration.from)) throw new Error("invalid migration chain");
    bySource.set(migration.from, migration);
  }
  while (version < target) {
    const migration = bySource.get(version);
    if (!migration) throw new Error(`missing migration ${version}`);
    candidate = migration.migrate(structuredClone(candidate));
    version = migration.to;
  }
  return candidate;
}

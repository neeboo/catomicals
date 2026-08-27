import type { CordisSettings } from "./settings.js";

export type CordisHealthStatus = "healthy" | "degraded" | "unhealthy" | "isolated";

export interface CordisHealthReport {
  readonly status: CordisHealthStatus;
  readonly code?: string;
  readonly message?: string;
  readonly checkedAt?: string;
}

export interface CordisServiceSnapshot {
  readonly name: string;
  readonly status: "healthy" | "degraded" | "unhealthy";
  readonly message?: string;
}

export interface CordisService {
  readonly name: string;
  health(): Promise<Omit<CordisServiceSnapshot, "name">>;
}

export type FixedHealthCheck = (context: {
  readonly settings: CordisSettings;
  readonly services: ReadonlyMap<string, CordisServiceSnapshot>;
}) => Promise<Omit<CordisHealthReport, "checkedAt" | "code">>;

export async function snapshotServices(
  names: readonly string[],
  services: ReadonlyMap<string, CordisService>,
): Promise<ReadonlyMap<string, CordisServiceSnapshot>> {
  const snapshots = new Map<string, CordisServiceSnapshot>();
  for (const name of names) {
    const service = services.get(name);
    if (!service) continue;
    try {
      snapshots.set(name, { name, ...await service.health() });
    } catch {
      snapshots.set(name, { name, status: "unhealthy", message: "service health check failed" });
    }
  }
  return snapshots;
}

export async function runHealthCheck(options: {
  readonly settings: CordisSettings;
  readonly requiredServices: readonly string[];
  readonly optionalServices: readonly string[];
  readonly services: ReadonlyMap<string, CordisService>;
  readonly check?: FixedHealthCheck;
  readonly checkedAt: string;
}): Promise<CordisHealthReport> {
  const names = [...new Set([...options.requiredServices, ...options.optionalServices])];
  const snapshots = await snapshotServices(names, options.services);
  const unhealthyRequired = options.requiredServices.find((name) => snapshots.get(name)?.status === "unhealthy");
  if (unhealthyRequired) {
    return { status: "unhealthy", code: "service_unhealthy", message: unhealthyRequired, checkedAt: options.checkedAt };
  }
  if (!options.check) return { status: "healthy", checkedAt: options.checkedAt };
  try {
    const report = await options.check({ settings: structuredClone(options.settings), services: snapshots });
    if (!["healthy", "degraded", "unhealthy"].includes(report.status)) throw new Error("invalid health status");
    return { ...report, checkedAt: options.checkedAt };
  } catch {
    return { status: "unhealthy", code: "health_check_failed", message: "plugin health check failed", checkedAt: options.checkedAt };
  }
}

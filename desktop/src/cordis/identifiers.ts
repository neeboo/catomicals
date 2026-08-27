const protocolUuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function parseSettingsReviewId(value: unknown): string {
  if (typeof value !== "string" || !protocolUuidPattern.test(value)) {
    throw new Error("invalid settings review");
  }
  return value.toLowerCase();
}

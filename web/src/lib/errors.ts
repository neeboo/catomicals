export function errorMessage(error: unknown, fallback = "Unknown error"): string {
  if (error instanceof Error && error.message) return error.message;
  if (typeof error === "string" && error) return error;

  try {
    if (error && typeof error === "object" && "message" in error) {
      const message = (error as { message?: unknown }).message;
      if (typeof message === "string" && message) return message;
    }
  } catch {
    return fallback;
  }

  return fallback;
}

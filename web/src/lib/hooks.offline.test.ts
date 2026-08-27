import { QueryClient, QueryObserver } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "./api";
import { createLiveQueryOptions, retryActiveWalletQueries } from "./hooks";

function offlineError(): ApiError {
  return new ApiError(0, "network_error", "Cannot reach the wallet node: offline");
}

describe("wallet node offline query policy", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("performs one initial load while offline even as observers receive error state", async () => {
    vi.useFakeTimers();
    const request = vi.fn().mockRejectedValue(offlineError());
    const client = new QueryClient();
    const options = createLiveQueryOptions({
      queryKey: ["wallet-node-status"],
      queryFn: request,
      refetchInterval: 10,
    });
    const observer = new QueryObserver(client, options);
    const unsubscribe = observer.subscribe(() => {
      observer.setOptions(options);
    });

    await vi.advanceTimersByTimeAsync(5_000);

    expect(request).toHaveBeenCalledTimes(1);
    expect(observer.getCurrentResult().error?.message).toContain("Cannot reach the wallet node");
    unsubscribe();
  });

  it("allows one explicit retry without starting an automatic retry loop", async () => {
    vi.useFakeTimers();
    const request = vi.fn().mockRejectedValue(offlineError());
    const client = new QueryClient();
    const observer = new QueryObserver(client, createLiveQueryOptions({
      queryKey: ["wallet-node-status"],
      queryFn: request,
      refetchInterval: 10,
    }));
    const unsubscribe = observer.subscribe(() => {});
    await vi.advanceTimersByTimeAsync(5_000);
    request.mockClear();

    const retry = retryActiveWalletQueries(client);
    await vi.advanceTimersByTimeAsync(5_000);
    await retry;

    expect(request).toHaveBeenCalledTimes(1);
    unsubscribe();
  });
});

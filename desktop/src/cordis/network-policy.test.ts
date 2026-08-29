import { describe, expect, it, vi } from "vitest";
import { assertRpcEndpointAccess } from "./network-policy.js";

describe("Cordis RPC network policy", () => {
  it("restricts local access to loopback targets", async () => {
    await expect(assertRpcEndpointAccess("http://127.0.0.1:8332", "local")).resolves.toBeUndefined();
    await expect(assertRpcEndpointAccess("http://[::1]:8332", "local")).resolves.toBeUndefined();
    await expect(assertRpcEndpointAccess("https://10.0.0.2", "local")).rejects.toThrow("loopback");
  });

  it("requires an explicit RFC1918 or ULA address for private access", async () => {
    await expect(assertRpcEndpointAccess("https://192.168.1.20", "private-network")).resolves.toBeUndefined();
    await expect(assertRpcEndpointAccess("https://[fd00::20]", "private-network")).resolves.toBeUndefined();
    await expect(assertRpcEndpointAccess("https://node.internal", "private-network", async () => ["10.0.0.2"]))
      .rejects.toThrow("explicit private address");
  });

  it("resolves public hosts and rejects local, private, link-local, and metadata targets", async () => {
    const publicResolver = vi.fn(async () => ["93.184.216.34"]);
    await expect(assertRpcEndpointAccess("https://rpc.example", "public", publicResolver)).resolves.toBeUndefined();
    expect(publicResolver).toHaveBeenCalledWith("rpc.example");

    for (const endpoint of [
      "http://127.0.0.1",
      "http://10.0.0.2",
      "http://169.254.169.254",
      "http://[::1]",
      "http://[fe80::1]",
      "http://metadata.google.internal",
    ]) {
      await expect(assertRpcEndpointAccess(endpoint, "public", async () => ["93.184.216.34"]))
        .rejects.toThrow(/blocked|non-public/);
    }
    await expect(assertRpcEndpointAccess("https://rebinding.example", "public", async () => ["93.184.216.34", "192.168.1.2"]))
      .rejects.toThrow("non-public");
  });
});

import { ipcMain, type IpcMainInvokeEvent } from "electron";
import { IPC_CHANNELS, parseIdentityLoginRequest, parseIpcArguments } from "../ipc.js";
import { IdentityServiceError, type IdentityService } from "./service.js";

interface IdentityIpcRegistrar {
  handle(channel: string, handler: (event: IpcMainInvokeEvent, ...args: unknown[]) => unknown): void;
  removeHandler(channel: string): void;
}

export interface IdentityIpcDeps {
  service: IdentityService;
  assertSender(event: IpcMainInvokeEvent): void;
  ipc?: IdentityIpcRegistrar;
}

export function registerIdentityIpc({ service, assertSender, ipc = ipcMain }: IdentityIpcDeps): () => void {
  const handlers: Array<[string, (event: IpcMainInvokeEvent, ...args: unknown[]) => unknown]> = [
    [IPC_CHANNELS.identityState, (_event, ...args) => {
      parseIpcArguments(args, 0);
      return invokeIdentity(() => service.state());
    }],
    [IPC_CHANNELS.identityLogin, (_event, ...args) => {
      const [request] = parseIpcArguments(args, 1);
      const parsed = parseIdentityLoginRequest(request);
      return invokeIdentity(() => service.login(parsed));
    }],
    [IPC_CHANNELS.identityLogout, (_event, ...args) => {
      parseIpcArguments(args, 0);
      return invokeIdentity(() => service.logout());
    }],
    [IPC_CHANNELS.identityRecover, (_event, ...args) => {
      parseIpcArguments(args, 0);
      return invokeIdentity(() => service.recover());
    }],
  ];
  for (const [channel, handler] of handlers) {
    ipc.handle(channel, (event, ...args) => {
      assertSender(event);
      return handler(event, ...args);
    });
  }
  return () => {
    for (const [channel] of handlers) ipc.removeHandler(channel);
  };
}

async function invokeIdentity<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error: unknown) {
    if (error instanceof IdentityServiceError) throw new Error(error.message);
    throw new Error("identity operation failed");
  }
}

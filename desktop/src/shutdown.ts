interface BeforeQuitEvent {
  preventDefault: () => void;
}

interface ShutdownResources {
  closeAgentBridge: () => Promise<void>;
  cleanupExecutors: () => Promise<void>;
  cleanupSigner: () => Promise<void>;
  cleanupWallet: () => Promise<void>;
  cleanupBrowser: () => Promise<void>;
  closeServer: () => Promise<void>;
  /** Flush pending session writes and close the search index. */
  closeSessions: () => Promise<void>;
  quit: () => void;
}

export class ShutdownCoordinator {
  private completed = false;
  private running: Promise<void> | null = null;

  constructor(private readonly resources: ShutdownResources) {}

  handleBeforeQuit(event: BeforeQuitEvent): Promise<void> {
    if (this.completed) return Promise.resolve();
    event.preventDefault();
    this.running ??= this.finishCleanup();
    return this.running;
  }

  private async finishCleanup(): Promise<void> {
    const failures: unknown[] = [];
    try {
      await this.resources.closeAgentBridge();
    } catch (error) {
      failures.push(error);
    }
    try {
      await this.resources.cleanupExecutors();
    } catch (error) {
      failures.push(error);
    }
    try {
      await this.resources.cleanupSigner();
    } catch (error) {
      failures.push(error);
    }
    try {
      await this.resources.cleanupWallet();
    } catch (error) {
      failures.push(error);
    }
    try {
      await this.resources.cleanupBrowser();
    } catch (error) {
      failures.push(error);
    }
    try {
      await this.resources.closeServer();
    } catch (error) {
      failures.push(error);
    }
    try {
      await this.resources.closeSessions();
    } catch (error) {
      failures.push(error);
    }
    this.completed = true;
    this.resources.quit();
    if (failures.length > 0) throw new AggregateError(failures, "desktop shutdown cleanup failed");
  }
}

/**
 * Mostly taken from
 * https://github.com/microsoft/vscode-languageserver-node/blob/main/client/src/node/processes.ts
 */

import { ChildProcess, execFileSync, spawnSync, spawn } from "child_process";
import { join } from "path";
import { Disposable } from "vscode";

const isWindows = process.platform === "win32";
const isMacintosh = process.platform === "darwin";
const isLinux = process.platform === "linux";

function terminate(process: ChildProcess & { pid: number }, cwd?: string): boolean {
    if (isWindows) {
        try {
            // This we run in Atom execFileSync is available.
            // Ignore stderr since this is otherwise piped to parent.stderr
            // which might be already closed.
            let options: any = {
                stdio: ["pipe", "pipe", "ignore"],
            };
            if (cwd) {
                options.cwd = cwd;
            }
            execFileSync(
                "taskkill",
                ["/T", "/F", "/PID", process.pid.toString()],
                options,
            );
            return true;
        } catch (err) {
            return false;
        }
    } else if (isLinux || isMacintosh) {
        try {
            var cmd = join(__dirname, "terminateProcess.sh");
            var result = spawnSync(cmd, [process.pid.toString()]);
            return result.error ? false : true;
        } catch (err) {
            return false;
        }
    } else {
        process.kill("SIGKILL");
        return true;
    }
}

export interface SubprocessSpawnOptions {
    cwd?: string;
    env?: any;
    detached?: boolean;
    shell?: boolean;
}

export interface SubprocessOptions {
    command: string;
    args?: string[];
    options?: SubprocessSpawnOptions;
}

export class VSCodeSubprocess implements Disposable {
    private readonly options: SubprocessOptions;
    private serverProcess: ChildProcess | undefined;
    private isDetached: boolean | undefined;
    private disposed: "disposing" | "disposed" | undefined;

    public constructor(options: SubprocessOptions) {
        this.options = options;
    }

    public start() {
        const args: string[] =
            this.options.args !== undefined ? this.options.args.slice(0) : [];
        const options = Object.assign({}, this.options.options);
        this.serverProcess = spawn(this.options.command, args, options);
        this.serverProcess.stderr?.on("data", (data) => {
            console.log("Stderr from server process:", data);
        });
        this.isDetached = !!options.detached;
    }

    private checkProcessDied(childProcess: ChildProcess | undefined): void {
        if (!childProcess || childProcess.pid === undefined) {
            return;
        }
        setTimeout(() => {
            try {
                if (childProcess.pid !== undefined) {
                    process.kill(childProcess.pid, <any>0);
                    terminate(childProcess as ChildProcess & { pid: number });
                }
            } catch (error) {
                console.log(
                    "Checked if process",
                    childProcess,
                    "was dead, and it was!",
                );
            }
        }, 2000);
    }

    public stop() {
        if (this.serverProcess) {
            const toCheck = this.serverProcess;
            this.serverProcess = undefined;
            if (this.isDetached === undefined || !this.isDetached) {
                this.checkProcessDied(toCheck);
            }
            this.isDetached = undefined;
        }
    }

    public async restart(): Promise<void> {
        this.stop();
        this.start();
    }

    public dispose(timeout: number = 2000) {
        try {
            return this.stop();
        } finally {
        }
    }
}

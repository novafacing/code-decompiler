import * as vscode from "vscode";
import * as grpc from "@grpc/grpc-js";
import { spawn, ChildProcess } from "child_process";
import { decfs } from "./decompfs";
import { basename } from "path";
import { dirname, join } from "path/posix";
import { TextEncoder } from "util";
import { DecompileRequest } from "./proto/server/proto/decompile_request";
import { DecompilerClient, PingMessage } from "./proto/server/proto/decompiler";
import { DecompileResult } from "./proto/server/proto/decompile_result";
import { SubprocessOptions, SubprocessSpawnOptions, VSCodeSubprocess } from "./process";
import { clear } from "console";

export class CodeDecompilerClient {
    private static client: CodeDecompilerClient | undefined;
    public fileSystem: decfs | undefined;
    private server: VSCodeSubprocess;
    private client: DecompilerClient;

    private waitUntilPong() {
        var tries = 0;
        const ping: PingMessage = new PingMessage({
            sequence: 1337,
        });
        var interval = setInterval(() => {
            try {
                const pong = this.client.Ping(ping, (err, message) => {
                    if (message !== undefined) {
                        console.log("Got pong: ", message.sequence);
                        clearInterval(interval);
                    }
                });
            } catch (e) {
                console.log(e);
            }
            tries++;
            if (tries++ > 10) {
                throw Error("Could not get pong in 10 tries!");
            }
        }, 1000);
    }

    constructor(private readonly context: vscode.ExtensionContext) {
        this.fileSystem = new decfs();
        console.log("Started server...");
        const spawnOptions: SubprocessSpawnOptions = {
            cwd: vscode.Uri.joinPath(context.extensionUri, "server").fsPath,
            detached: true,
        };
        const options: SubprocessOptions = {
            command: "poetry",
            args: ["run", "python3", "-m", "server"],
            options: spawnOptions,
        };
        this.server = new VSCodeSubprocess(options);
        this.server.start();
        console.log("Starting client...");
        this.client = new DecompilerClient(
            "localhost:8080",
            grpc.credentials.createInsecure(),
        );
        grpc.waitForClientReady(this.client, Date.now() + 5000, (err) => {
            if (err !== undefined) {
                console.log(err);
            }
        });
        this.waitUntilPong();
    }

    stop() {
        this.server.stop();
    }

    decompile(file: vscode.Uri): { [key: string]: string } {
        const fileName = basename(file.fsPath);
        const filePath = this.fileSystem?.getDecompTarget(fileName);
        if (filePath === undefined) {
            throw new Error("Unable to decompile: " + file);
        }

        let request: DecompileRequest = new DecompileRequest({
            filename: fileName,
            binary: this.fileSystem?.readFile(filePath) ?? new TextEncoder().encode(""),
        });

        let decompilation: { [key: string]: string } = {};

        const decompileResponse = this.client.Decompile(request);

        decompileResponse.on("status", (status) => {
            console.log("Got decompile status: ", status);
        });

        decompileResponse.on("data", (res: DecompileResult) => {
            console.log("Got decompile response: ", res.decompilation);
            const functionOutputPath = join(
                dirname(filePath.fsPath),
                res.function + ".c",
            );
            console.log("Writing decompile result to: ", functionOutputPath);
            decompilation[res.function] = res.decompilation;
            this.fileSystem?.writeFile(
                filePath.with({ path: functionOutputPath }),
                new TextEncoder().encode(res.decompilation),
                { create: true, overwrite: true },
            );
        });
        decompileResponse.on("end", () => {
            console.log("Finished decompiling.");
        });

        decompileResponse.on("error", (err: Error) => {
            console.log("Error decompiling: ", err);
            throw err;
        });

        return decompilation;
    }

    static getClient(
        context: vscode.ExtensionContext,
        file?: vscode.Uri,
    ): CodeDecompilerClient {
        console.log("Getting decompiler client...");
        if (CodeDecompilerClient.client === undefined) {
            CodeDecompilerClient.client = new CodeDecompilerClient(context);
            vscode.workspace.updateWorkspaceFolders(0, 0, {
                uri: vscode.Uri.parse("decfs:/"),
                name: "Decompile Results",
            });
        }

        const client = CodeDecompilerClient.client;

        if (file !== undefined) {
            client.fileSystem?.addDecompTarget(file);
            client.decompile(file);
        }

        console.log("Got client...");
        return client;
    }
}

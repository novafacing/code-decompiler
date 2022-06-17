import * as vscode from "vscode";
import * as grpc from "@grpc/grpc-js";
import { spawn, ChildProcess } from "child_process";
import { decfs } from "./decompfs";
import { basename } from "path";
import { dirname } from "path/posix";
import { TextEncoder } from "util";
import { DecompileRequest } from "./proto/server/proto/decompile_request";
import { DecompilerClient } from "./proto/server/proto/decompiler";
import { DecompileResult } from "./proto/server/proto/decompile_result";
import { SubprocessOptions, SubprocessSpawnOptions, VSCodeSubprocess } from "./process";

export class CodeDecompilerClient {
    private static client: CodeDecompilerClient | undefined;
    public fileSystem: decfs | undefined;
    private server: VSCodeSubprocess;
    private client: DecompilerClient;

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
        };
        this.server = new VSCodeSubprocess(options);
        this.server.start();
        console.log("Starting client...");
        this.client = new DecompilerClient(
            "127.0.0.1:8080",
            grpc.credentials.createInsecure(),
        );
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
            decompilation[res.function] = res.decompilation;
            this.fileSystem?.writeFile(
                filePath.with({ path: dirname(filePath.fsPath) }),
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

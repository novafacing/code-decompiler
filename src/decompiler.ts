import * as vscode from "vscode";
import { spawn, ChildProcess } from "child_process";
import { decfs } from "./decompfs";

export class DecompilerClient {
    private static client: DecompilerClient | undefined;
    public fileSystem: decfs | undefined;
    private server: ChildProcess;

    constructor(private readonly context: vscode.ExtensionContext) {
        this.fileSystem = new decfs();
        this.server = spawn("poetry", ["run", "python3", "-m", "server"], {
            cwd: vscode.Uri.joinPath(context.extensionUri, "server").fsPath,
            detached: true,
        }).on("error", (err) => {
            throw err;
        });
    }

    static getClient(
        context: vscode.ExtensionContext,
        file?: vscode.Uri,
    ): DecompilerClient {
        console.log("Getting decompiler client...");
        if (DecompilerClient.client === undefined) {
            DecompilerClient.client = new DecompilerClient(context);
            vscode.workspace.updateWorkspaceFolders(0, 0, {
                uri: vscode.Uri.parse("decfs:/"),
                name: "Decompile Results",
            });
        }

        const client = DecompilerClient.client;

        if (file !== undefined) {
            client.fileSystem?.addDecompTarget(file);
        }

        console.log("Got client...");
        return client;
    }
}

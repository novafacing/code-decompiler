import * as vscode from "vscode";

import { DecompilerClient } from "./decompiler";

export function activate(context: vscode.ExtensionContext) {
    console.log("Registering decompile command...");

    const client = DecompilerClient.getClient(context);

    const fs = client.fileSystem ?? null;

    if (fs === null) {
        throw Error("Couldn't get FS!");
    }

    context.subscriptions.push(
        vscode.workspace.registerFileSystemProvider("decfs", fs, {
            isCaseSensitive: true,
        }),
    );
    let decompileCommand = vscode.commands.registerCommand(
        "code-decompiler.decompile",
        async (file: vscode.Uri) => {
            if (file) {
                console.log("Decompiling file: ", file);
            }
            let decompilerClient = DecompilerClient.getClient(context, file);
        },
    );

    context.subscriptions.push(decompileCommand);
}

export function deactivate() {}

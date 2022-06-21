import * as vscode from "vscode";

import { CodeDecompilerClient } from "./decompiler";

export var vscodeContext: vscode.ExtensionContext;
export var mainClient: CodeDecompilerClient;

export function activate(context: vscode.ExtensionContext) {
    console.log("Registering decompile command...");

    vscodeContext = context;

    const client = CodeDecompilerClient.getClient(context);
    mainClient = client;

    let decompileCommand = vscode.commands.registerCommand(
        "code-decompiler.decompile",
        async (file: vscode.Uri) => {
            if (file) {
                console.log("Decompiling file: ", file);
            }
            mainClient = CodeDecompilerClient.getClient(context, file);
        },
    );

    context.subscriptions.push(decompileCommand);
}

export function deactivate() {
    mainClient.stop();
}

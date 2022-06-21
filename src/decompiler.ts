import * as vscode from "vscode";
import * as grpc from "@grpc/grpc-js";
import { basename } from "path";
import { dirname, join } from "path/posix";
import { TextEncoder } from "util";
import {
    DecompilerBackend,
    DecompileRequest,
} from "./proto/server/proto/decompile_request";
import { DecompilerClient, PingMessage } from "./proto/server/proto/decompiler";
import { DecompileResult } from "./proto/server/proto/decompile_result";
import { SubprocessOptions, SubprocessSpawnOptions, VSCodeSubprocess } from "./process";
import { mkdir, readFileSync, writeFileSync } from "fs";
import { mapUriDefaultScheme } from "@grpc/grpc-js/build/src/resolver";

export class CodeDecompilerClient {
    private static client: CodeDecompilerClient | undefined;
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

    decompile(file: vscode.Uri): void {
        const fileName = basename(file.fsPath);
        const filePath = file;
        const fileContents = readFileSync(filePath.fsPath);
        const decompileDir = join(dirname(filePath.fsPath), fileName + ".decompiled");
        const typesFilePath = join(decompileDir, "types.h");

        mkdir(decompileDir, (err) => {
            if (err === null) {
                console.log("Error:", err);
            }
        });

        if (filePath === undefined) {
            throw new Error("Unable to decompile: " + file);
        }

        let request: DecompileRequest = new DecompileRequest({
            filename: fileName,
            decompiler: DecompilerBackend.binaryninja,
            binary: fileContents,
        });

        const decompileResponse = this.client.Decompile(request);
        let types = {
            includes:
                "#include <stdarg.h>\n" +
                "#include <stdbool.h>\n" +
                "#include <stddef.h>\n" +
                "#include <stdint.h>\n" +
                "#include <stdio.h>\n" +
                "#include <stdlib.h>\n",
        };

        decompileResponse.on("status", (status) => {
            console.log("Got decompile status: ", status);
        });

        decompileResponse.on("data", (res: DecompileResult) => {
            console.log("Got result: ", res);
            const functionOutputPath = join(
                dirname(filePath.fsPath),
                basename(filePath.fsPath) + ".decompiled",
                res.function + ".c",
            );

            writeFileSync(
                filePath.with({ path: functionOutputPath }).fsPath,
                new TextEncoder().encode(`#include "types.h"\n` + res.decompilation),
            );

            types = Object.assign({}, types, res.types);
        });

        decompileResponse.on("end", () => {
            console.log("Finished decompiling. Have types: ", types);
            writeFileSync(
                typesFilePath,
                Object.values(types)
                    // .map((v, i, a) => {
                    //     return new TextEncoder().encode(v);
                    // })
                    .join("\n"),
            );
        });

        decompileResponse.on("error", (err: Error) => {
            console.log("Error decompiling: ", err.message);
            throw err;
        });
    }

    static getClient(
        context: vscode.ExtensionContext,
        file?: vscode.Uri,
    ): CodeDecompilerClient {
        console.log("Getting decompiler client...");
        if (CodeDecompilerClient.client === undefined) {
            CodeDecompilerClient.client = new CodeDecompilerClient(context);
        }

        const client = CodeDecompilerClient.client;

        if (file !== undefined) {
            client.decompile(file);
        }

        console.log("Got client...");
        return client;
    }
}

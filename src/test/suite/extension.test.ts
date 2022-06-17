import * as assert from "assert";

import * as vscode from "vscode";
import * as grpc from "@grpc/grpc-js";
import * as decompilerExtension from "../../extension";
import {
    SubprocessOptions,
    SubprocessSpawnOptions,
    VSCodeSubprocess,
} from "../../process";
import { DecompilerClient, PingMessage } from "../../proto/server/proto/decompiler";

suite("Code Decompiler test suite", () => {
    vscode.window.showInformationMessage("Start all tests.");

    test("Test talking to the python server", async () => {
        const spawnOptions: SubprocessSpawnOptions = {
            cwd: vscode.Uri.joinPath(
                decompilerExtension.vscodeContext.extensionUri,
                "server",
            ).fsPath,
            detached: false,
        };
        const options: SubprocessOptions = {
            command: "poetry",
            args: ["run", "python3", "-m", "server"],
            options: spawnOptions,
        };
        const server = new VSCodeSubprocess(options);
        server.start();
        const client = new DecompilerClient(
            "127.0.0.1:8080",
            grpc.credentials.createInsecure(),
        );

        grpc.waitForClientReady(client, Date.now() + 5000, (err) => {
            if (err !== undefined) {
                console.log(err);
            }
        });

        const ping: PingMessage = new PingMessage({
            sequence: 1337,
        });
        for (let i = 0; i < 10; i++) {
            try {
                const pong = client.Ping(ping, (err, message) => {
                    if (message !== undefined) {
                        console.log("Got pong: ", message.sequence);
                        assert.equal(
                            message.sequence,
                            ping.sequence,
                            "Sequence numbers not equal!",
                        );
                    }
                    assert.equal(err, null, "Error thrown: " + err);
                });
                server.stop();
                break;
            } catch (e) {
                console.log(e);
            }
        }
    });
});

/**
 * Generated by the protoc-gen-ts.  DO NOT EDIT!
 * compiler version: 3.12.4
 * source: server/proto/decompile_request.proto
 * git: https://github.com/thesayyn/protoc-gen-ts */
import * as pb_1 from "google-protobuf";
export enum DecompilerBackend {
    binaryninja = 0,
    angr = 1,
    ghidra = 2
}
export class DecompileRequest extends pb_1.Message {
    #one_of_decls: number[][] = [];
    constructor(data?: any[] | {
        filename?: string;
        decompiler?: DecompilerBackend;
        binary?: Uint8Array;
    }) {
        super();
        pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
        if (!Array.isArray(data) && typeof data == "object") {
            if ("filename" in data && data.filename != undefined) {
                this.filename = data.filename;
            }
            if ("decompiler" in data && data.decompiler != undefined) {
                this.decompiler = data.decompiler;
            }
            if ("binary" in data && data.binary != undefined) {
                this.binary = data.binary;
            }
        }
    }
    get filename() {
        return pb_1.Message.getField(this, 1) as string;
    }
    set filename(value: string) {
        pb_1.Message.setField(this, 1, value);
    }
    get decompiler() {
        return pb_1.Message.getField(this, 2) as DecompilerBackend;
    }
    set decompiler(value: DecompilerBackend) {
        pb_1.Message.setField(this, 2, value);
    }
    get binary() {
        return pb_1.Message.getField(this, 3) as Uint8Array;
    }
    set binary(value: Uint8Array) {
        pb_1.Message.setField(this, 3, value);
    }
    static fromObject(data: {
        filename?: string;
        decompiler?: DecompilerBackend;
        binary?: Uint8Array;
    }): DecompileRequest {
        const message = new DecompileRequest({});
        if (data.filename != null) {
            message.filename = data.filename;
        }
        if (data.decompiler != null) {
            message.decompiler = data.decompiler;
        }
        if (data.binary != null) {
            message.binary = data.binary;
        }
        return message;
    }
    toObject() {
        const data: {
            filename?: string;
            decompiler?: DecompilerBackend;
            binary?: Uint8Array;
        } = {};
        if (this.filename != null) {
            data.filename = this.filename;
        }
        if (this.decompiler != null) {
            data.decompiler = this.decompiler;
        }
        if (this.binary != null) {
            data.binary = this.binary;
        }
        return data;
    }
    serialize(): Uint8Array;
    serialize(w: pb_1.BinaryWriter): void;
    serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
        const writer = w || new pb_1.BinaryWriter();
        if (typeof this.filename === "string" && this.filename.length)
            writer.writeString(1, this.filename);
        if (this.decompiler !== undefined)
            writer.writeEnum(2, this.decompiler);
        if (this.binary !== undefined)
            writer.writeBytes(3, this.binary);
        if (!w)
            return writer.getResultBuffer();
    }
    static deserialize(bytes: Uint8Array | pb_1.BinaryReader): DecompileRequest {
        const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new DecompileRequest();
        while (reader.nextField()) {
            if (reader.isEndGroup())
                break;
            switch (reader.getFieldNumber()) {
                case 1:
                    message.filename = reader.readString();
                    break;
                case 2:
                    message.decompiler = reader.readEnum();
                    break;
                case 3:
                    message.binary = reader.readBytes();
                    break;
                default: reader.skipField();
            }
        }
        return message;
    }
    serializeBinary(): Uint8Array {
        return this.serialize();
    }
    static deserializeBinary(bytes: Uint8Array): DecompileRequest {
        return DecompileRequest.deserialize(bytes);
    }
}

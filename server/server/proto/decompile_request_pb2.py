# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: server/proto/decompile_request.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n$server/proto/decompile_request.proto\"\\\n\x10\x44\x65\x63ompileRequest\x12\x10\n\x08\x66ilename\x18\x01 \x01(\t\x12&\n\ndecompiler\x18\x02 \x01(\x0e\x32\x12.DecompilerBackend\x12\x0e\n\x06\x62inary\x18\x03 \x01(\x0c*:\n\x11\x44\x65\x63ompilerBackend\x12\x0f\n\x0b\x62inaryninja\x10\x00\x12\x08\n\x04\x61ngr\x10\x01\x12\n\n\x06ghidra\x10\x02\x62\x06proto3')

_DECOMPILERBACKEND = DESCRIPTOR.enum_types_by_name['DecompilerBackend']
DecompilerBackend = enum_type_wrapper.EnumTypeWrapper(_DECOMPILERBACKEND)
binaryninja = 0
angr = 1
ghidra = 2


_DECOMPILEREQUEST = DESCRIPTOR.message_types_by_name['DecompileRequest']
DecompileRequest = _reflection.GeneratedProtocolMessageType('DecompileRequest', (_message.Message,), {
  'DESCRIPTOR' : _DECOMPILEREQUEST,
  '__module__' : 'server.proto.decompile_request_pb2'
  # @@protoc_insertion_point(class_scope:DecompileRequest)
  })
_sym_db.RegisterMessage(DecompileRequest)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _DECOMPILERBACKEND._serialized_start=134
  _DECOMPILERBACKEND._serialized_end=192
  _DECOMPILEREQUEST._serialized_start=40
  _DECOMPILEREQUEST._serialized_end=132
# @@protoc_insertion_point(module_scope)

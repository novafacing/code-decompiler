# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

from server.proto import decompile_request_pb2 as server_dot_proto_dot_decompile__request__pb2
from server.proto import decompile_result_pb2 as server_dot_proto_dot_decompile__result__pb2
from server.proto import decompile_update_pb2 as server_dot_proto_dot_decompile__update__pb2
from server.proto import decompiler_pb2 as server_dot_proto_dot_decompiler__pb2


class DecompilerStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.Decompile = channel.unary_stream(
                '/Decompiler/Decompile',
                request_serializer=server_dot_proto_dot_decompile__request__pb2.DecompileRequest.SerializeToString,
                response_deserializer=server_dot_proto_dot_decompile__result__pb2.DecompileResult.FromString,
                )
        self.Update = channel.unary_unary(
                '/Decompiler/Update',
                request_serializer=server_dot_proto_dot_decompile__update__pb2.DecompileUpdate.SerializeToString,
                response_deserializer=server_dot_proto_dot_decompile__result__pb2.DecompileResult.FromString,
                )
        self.Ping = channel.unary_unary(
                '/Decompiler/Ping',
                request_serializer=server_dot_proto_dot_decompiler__pb2.PingMessage.SerializeToString,
                response_deserializer=server_dot_proto_dot_decompiler__pb2.PongMessage.FromString,
                )


class DecompilerServicer(object):
    """Missing associated documentation comment in .proto file."""

    def Decompile(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Update(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Ping(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_DecompilerServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'Decompile': grpc.unary_stream_rpc_method_handler(
                    servicer.Decompile,
                    request_deserializer=server_dot_proto_dot_decompile__request__pb2.DecompileRequest.FromString,
                    response_serializer=server_dot_proto_dot_decompile__result__pb2.DecompileResult.SerializeToString,
            ),
            'Update': grpc.unary_unary_rpc_method_handler(
                    servicer.Update,
                    request_deserializer=server_dot_proto_dot_decompile__update__pb2.DecompileUpdate.FromString,
                    response_serializer=server_dot_proto_dot_decompile__result__pb2.DecompileResult.SerializeToString,
            ),
            'Ping': grpc.unary_unary_rpc_method_handler(
                    servicer.Ping,
                    request_deserializer=server_dot_proto_dot_decompiler__pb2.PingMessage.FromString,
                    response_serializer=server_dot_proto_dot_decompiler__pb2.PongMessage.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'Decompiler', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class Decompiler(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def Decompile(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_stream(request, target, '/Decompiler/Decompile',
            server_dot_proto_dot_decompile__request__pb2.DecompileRequest.SerializeToString,
            server_dot_proto_dot_decompile__result__pb2.DecompileResult.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def Update(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/Decompiler/Update',
            server_dot_proto_dot_decompile__update__pb2.DecompileUpdate.SerializeToString,
            server_dot_proto_dot_decompile__result__pb2.DecompileResult.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def Ping(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/Decompiler/Ping',
            server_dot_proto_dot_decompiler__pb2.PingMessage.SerializeToString,
            server_dot_proto_dot_decompiler__pb2.PongMessage.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)
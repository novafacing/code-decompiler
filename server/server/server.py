"""
Main gRPC server implementation
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Iterable, Optional

from binaryninja import BinaryView, BinaryViewType  # pylint: disable=import-error
from grpc import server
from grpc._server import _Server

from server.proto.decompile_request_pb2 import DecompileRequest
from server.proto.decompile_result_pb2 import DecompileResult
from server.proto.decompiler_pb2_grpc import (
    add_DecompilerServicer_to_server,
    DecompilerServicer,
)


class DecompilerServer(DecompilerServicer):
    """
    DecompilerServicer class
    """

    def __init__(self, host: str, port: int) -> None:
        """
        Constructor
        """
        self.host = host
        self.port = port
        self.binaries: Dict[str, BinaryView] = {}
        self.server: Optional[_Server] = None

    def Decompile(
        self, request: DecompileRequest, context
    ) -> Iterable[DecompileResult]:
        """
        Decompile method
        """
        if request.filename not in self.binaries:
            self.binaries[request.filename] = BinaryViewType.load(request.filename)

        binary = self.binaries[request.filename]
        for function in binary.functions:
            print("Decompiling function:", function.name)
            lines = " ".join(map(str, function.hlil.lines))
            yield DecompileResult(function.name, lines)

    def run(self) -> None:
        """
        Run server
        """
        self.server = server(ThreadPoolExecutor(max_workers=1))
        add_DecompilerServicer_to_server(self, self.server)
        self.server.add_insecure_port(f"{self.host}:{self.port}")
        self.server.start()
        self.server.wait_for_termination()

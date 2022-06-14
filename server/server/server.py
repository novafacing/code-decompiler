"""
Main gRPC server implementation
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Iterable, Optional
from logging import DEBUG, basicConfig, getLogger

from binaryninja import BinaryView, BinaryViewType  # pylint: disable=import-error
from grpc import server
from grpc._server import _Server

from server.proto.decompile_request_pb2 import DecompileRequest
from server.proto.decompile_result_pb2 import DecompileResult
from server.proto.decompiler_pb2_grpc import (
    add_DecompilerServicer_to_server,
    DecompilerServicer,
)

basicConfig(filename="server.log", encoding="utf-8", level=DEBUG)
logger = getLogger(__name__)


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
        logger.info(f"Running server on {self.host}:{self.port}")
        self.binaries: Dict[str, BinaryView] = {}
        self.server: Optional[_Server] = None

    def Decompile(
        self, request: DecompileRequest, context
    ) -> Iterable[DecompileResult]:
        """
        Decompile method
        """
        logger.info(f"Request for decompilation received for {request}")
        if request.filename not in self.binaries:
            self.binaries[request.filename] = BinaryViewType.load(request.filename)

        binary = self.binaries[request.filename]
        for function in binary.functions:
            logger.info(f"Decompiling function: {function.name}")
            lines = " ".join(map(str, function.hlil.lines))
            yield DecompileResult(function.name, lines)

    def run(self) -> None:
        """
        Run server
        """
        self.server = server(ThreadPoolExecutor(max_workers=1))
        add_DecompilerServicer_to_server(self, self.server)
        self.server.add_insecure_port(f"{self.host}:{self.port}")
        logger.info(
            f"Starting server on {self.host}:{self.port} and accepting connections."
        )
        self.server.start()
        self.server.wait_for_termination()

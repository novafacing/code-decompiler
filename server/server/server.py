"""
Main gRPC server implementation
"""

from concurrent.futures import ThreadPoolExecutor
from itertools import chain
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
from server.proto.decompiler_pb2 import (
    PingMessage,
    PongMessage,
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

    def Ping(self, request: PingMessage, context) -> PongMessage:
        """
        Ping method
        """
        logger.info(f"Ping received: {request.sequence}")
        return PingMessage(sequence=request.sequence)

    def Decompile(
        self, request: DecompileRequest, context
    ) -> Iterable[DecompileResult]:
        """
        Decompile method
        """
        logger.info(f"Request for decompilation received for {request.filename}")

        if request.filename not in self.binaries:
            logger.info(
                f"{request.filename} not found in cache. Loading it from {request.binary[:64]}..."
            )

            self.binaries[request.filename] = BinaryViewType.load(request.binary)
            logger.info(f"{request.filename} loaded: {self.binaries[request.filename]}")

        binary = self.binaries[request.filename]

        if binary is None or not hasattr(binary, "functions"):
            raise Exception(
                f"{request.filename} not found, or binary {request.binary[:64]}... is invalid"
            )

        for function in binary.functions:
            logger.info(f"Decompiling function: {function.name}")

            lines = str(function.function_type) + " {\n"
            lines += "\n".join(
                chain(*map(lambda i: map(str, i.lines), function.hlil.instructions))
            )
            lines += "\n}"
            yield DecompileResult(function=function.name, decompilation=lines)

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

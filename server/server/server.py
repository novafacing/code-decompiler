"""
Main gRPC server implementation
"""

from abc import abstractmethod
from concurrent.futures import ThreadPoolExecutor
from itertools import chain
from typing import Dict, Iterable, Optional
from logging import DEBUG, basicConfig, getLogger

from tree_sitter import Language, Parser, Node, Tree, TreeCursor

from binaryninja import BinaryView, BinaryViewType  # pylint: disable=import-error
from binaryninja.function import DisassemblySettings, DisassemblyOption
from binaryninja.lineardisassembly import LinearViewObject, LinearViewCursor

from grpc import server
from grpc._server import _Server

from server.proto.decompile_request_pb2 import DecompileRequest, DecompilerBackend
from server.proto.decompile_result_pb2 import DecompileResult
from server.proto.decompile_update_pb2 import DecompileUpdate
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


class Decompilation:
    """
    Abstract base class for decompilation backends
    """

    def __init__(self, decompile_request: DecompileRequest) -> None:
        """
        Base initializer for decompilation backends
        """
        self.request = decompile_request
        self.filename = decompile_request.filename
        self.binary = decompile_request.binary

    @abstractmethod
    def result(self) -> Iterable[DecompileResult]:
        """
        Abstract method for getting the result of the decompilation
        """
        raise NotImplementedError

    @abstractmethod
    def update(self, update: DecompileUpdate) -> None:
        """
        Abstract method to update the decompilation with the state of the source
        files
        """
        raise NotImplementedError


class BinaryNinjaDecompilation(Decompilation):
    """
    Represents the decompilation of a binary file
    """

    functions: Dict[str, str] = {}
    asts: Dict[str, Tree] = {}
    types: Dict[str, str] = {}
    bv: BinaryView

    def __init__(self, decompile_request: DecompileRequest) -> None:
        """
        Constructor
        """
        super().__init__(decompile_request)
        self.bv = BinaryViewType.load(self.binary)
        self._get_functions()
        self._get_types()

    def _get_functions(self) -> None:
        """
        Get each function's decompilation from Binary Ninja
        """
        for function in self.bv.functions:
            # https://gist.github.com/psifertex/6fbc7532f536775194edd26290892ef7#file-pseudo_c-py
            settings = DisassemblySettings()
            settings.set_option(DisassemblyOption.ShowAddress, False)
            lvo = LinearViewObject.language_representation(self.bv, settings)
            cursor_end = LinearViewCursor(lvo)
            cursor_end.seek_to_address(function.highest_address)
            body = self.bv.get_next_linear_disassembly_lines(cursor_end)
            cursor_end.seek_to_address(function.highest_address)
            header = self.bv.get_previous_linear_disassembly_lines(cursor_end)

            logger.info(f"Decompiling function: {function.name}")
            lines = "\n".join(map(str, chain(header, body))) + "\n"
            self.functions[function.name] = lines

    def _get_types(self) -> None:
        """
        Get all the program's types from Binary Ninja
        """
        for name, typ in self.bv.types.items():
            try:
                self.types[name] = "\n".join(map(str, typ.get_lines(self.bv, name)))
            except Exception as e:
                logger.error(f"Failed to get type {name}: {e}")

    def result(self) -> Iterable[DecompileResult]:
        """
        Get the decompiler results
        """
        for name, function in self.functions.items():
            yield DecompileResult(
                filename=self.filename,
                function=name,
                decompilation=function,
                types=self.types,
            )

    def update(self, update: DecompileUpdate) -> None:
        """
        Update the decompilation with the state of the source files
        """
        raise NotImplementedError


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

            if (
                not request.decompiler
                or request.decompiler == DecompilerBackend.binaryninja
            ):
                self.binaries[request.filename] = BinaryNinjaDecompilation(request)

            logger.info(f"{request.filename} loaded: {self.binaries[request.filename]}")

        decompile = self.binaries[request.filename]

        if decompile is None:
            raise Exception(
                f"{request.filename} not found, or binary {request.binary[:64]}... is invalid"
            )

        for result in decompile.result():
            yield result

    def Update(self, request: DecompileUpdate, context) -> None:
        """
        Update method
        """
        logger.info(f"Update received for {request.filename}")

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

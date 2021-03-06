"""
Server CLI entrypoint
"""

from argparse import ArgumentParser

from server.server import DecompilerServer


parser = ArgumentParser(prog="server")
parser.add_argument("--host", required=False, type=str, default="localhost")
parser.add_argument("--port", required=False, type=int, default=8080)
args = parser.parse_args()
server = DecompilerServer(args.host, args.port)
server.run()

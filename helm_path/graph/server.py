from __future__ import annotations

import contextlib
import functools
import threading
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


@contextlib.contextmanager
def serve_graph_dir(graph_dir: Path, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True):
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(graph_dir))
    server = ThreadingHTTPServer((host, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    actual_host, actual_port = server.server_address[:2]
    url = f"http://{actual_host}:{actual_port}/index.html"
    if open_browser:
        webbrowser.open(url)
    try:
        yield server, url
    finally:
        server.shutdown()
        server.server_close()

"""Fixture-only live metadata canary or bounded relay to the real broker admin API."""

import asyncio
import http.server
import sys


async def relay(host):
    slots = asyncio.Semaphore(32)

    async def connect(reader, writer):
        if slots.locked():
            writer.close()
            return
        async with slots:
            other = None
            try:
                remote, other = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", 9644), 3
                )

                async def pipe(source, target):
                    while data := await asyncio.wait_for(source.read(16384), 5):
                        target.write(data)
                        await target.drain()

                jobs = [
                    asyncio.create_task(pipe(reader, other)),
                    asyncio.create_task(pipe(remote, writer)),
                ]
                _, pending = await asyncio.wait(jobs, return_when=asyncio.FIRST_COMPLETED)
                for job in pending:
                    job.cancel()
                await asyncio.gather(*jobs, return_exceptions=True)
            except OSError, TimeoutError:
                pass
            finally:
                writer.close()
                if other is not None:
                    other.close()

    server = await asyncio.start_server(connect, host, 9644)
    async with server:
        await server.serve_forever()


class Metadata(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        data = b"SYNTHETIC_METADATA_NOT_A_CREDENTIAL"
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    if sys.argv[1] == "metadata":
        http.server.ThreadingHTTPServer(("0.0.0.0", 18080), Metadata).serve_forever()
    else:
        asyncio.run(relay(sys.argv[2]))

"""Bridge regressions using synthetic RTSP/WebSocket traffic only."""
import asyncio
import logging
import ssl
import unittest
from unittest.mock import patch

import websockets

from kuna_server import KunaWS, rtsp_server


class Client:
    peername = 'synthetic:1234'
    host = 'synthetic'
    tcp_port = 1234

    def __init__(self):
        self.requests = asyncio.Queue()
        self.output = bytearray()
        self.closed = asyncio.Event()
        self.output_changed = asyncio.Event()
        self.read_started = asyncio.Event()

    async def read(self, size):
        self.read_started.set()
        return await self.requests.get()

    async def write(self, data):
        self.output.extend(data)
        self.output_changed.set()

    async def close(self):
        if not self.closed.is_set():
            self.closed.set()
            self.requests.put_nowait(b'')


class PendingConnection:
    async def __aenter__(self):
        await asyncio.Event().wait()

    async def __aexit__(self, *args):
        pass


def proxy_message(kind, payload=b'', channel=7):
    return b''.join(n.to_bytes(4, 'big') for n in (kind, channel, channel, len(payload))) + payload


class WebSocket:
    def __init__(self, setup=True, channel=7, setup_after=1):
        self.messages = asyncio.Queue()
        self.request_forwarded = asyncio.Event()
        self.closed = asyncio.Event()
        self.setup = setup
        self.channel = channel
        self.setup_after = setup_after
        self.setup_requests = 0

    async def send(self, data):
        if data[:4] == (7).to_bytes(4, 'big'):
            self.setup_requests += 1
            if self.setup and self.setup_requests >= self.setup_after:
                setup = b''.join(n.to_bytes(4, 'big') for n in (8, 0, 0, 0, 0, self.channel, 0, 0))
                self.messages.put_nowait(setup)
        elif data[:4] == (4).to_bytes(4, 'big'):
            self.request_forwarded.set()

    async def recv(self):
        message = await self.messages.get()
        if isinstance(message, Exception):
            raise message
        return message

    async def close(self):
        self.closed.set()


class Connection:
    def __init__(self, websocket, delay=0, error=None):
        self.websocket = websocket
        self.delay = delay
        self.error = error
        self.started = asyncio.Event()
        self.finished = asyncio.Event()

    async def __aenter__(self):
        self.started.set()
        try:
            await asyncio.sleep(self.delay)
            if self.error:
                raise self.error
            return self.websocket
        finally:
            self.finished.set()

    async def __aexit__(self, *args):
        await self.websocket.close()


class BridgeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.previous_tasks = asyncio.all_tasks()
        self.connect = patch('kuna_server.websockets.connect', return_value=PendingConnection())
        self.connect_mock = self.connect.start()
        self.client = Client()
        self.bridge = None

    def start_bridge(self, connection=None):
        if connection is not None:
            self.connect_mock.return_value = connection
        self.bridge = KunaWS('synthetic-camera', 4554, 'synthetic-token', self.client)
        return self.bridge

    async def asyncTearDown(self):
        if self.bridge is not None:
            await self.bridge.close()
        tasks = asyncio.all_tasks() - self.previous_tasks - {asyncio.current_task()}
        orphaned = [task for task in tasks if task.get_coro().__qualname__.startswith('KunaWS.')]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.connect.stop()
        self.assertEqual(orphaned, [], 'Bridge tasks survived session cleanup')

    async def test_tcp_forwarding_preserves_fragmented_and_control_bytes(self):
        self.start_bridge()
        # A single RTP record split at its interleaved header and payload.
        rtp = b'\x80\x60\x00\x01\x00\x00\x00\x01\x11\x22\x33\x44payload'
        frame = b'$\x00' + len(rtp).to_bytes(2, 'big') + rtp
        rtcp = b'$\x01\x00\x08\x80\xc8\x00\x01\x11\x22\x33\x44'
        for chunk in (frame[:3], frame[3:6], frame[6:], rtcp):
            await self.bridge.send_to_tcp(chunk)
        self.assertEqual(bytes(self.client.output), frame + rtcp)

    async def test_slow_handshake_keeps_client_open_until_setup(self):
        websocket = WebSocket()
        self.start_bridge(Connection(websocket, delay=1.1))
        self.client.requests.put_nowait(b'OPTIONS rtsp://synthetic/stream2 RTSP/1.0\r\nCSeq: 1\r\n\r\n')
        await asyncio.wait_for(websocket.request_forwarded.wait(), timeout=2.5)
        self.assertFalse(self.client.closed.is_set())

    async def test_upstream_tls_verifies_hostname_and_certificate(self):
        websocket = WebSocket()
        self.start_bridge(Connection(websocket))
        self.client.requests.put_nowait(b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n')
        await asyncio.wait_for(websocket.request_forwarded.wait(), timeout=0.5)
        context = self.connect_mock.call_args.kwargs['ssl']
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    async def test_close_releases_udp_socket(self):
        self.start_bridge()
        await self.bridge.close()
        self.assertEqual(self.bridge.udp_sock.fileno(), -1)

    async def test_close_cancels_inflight_handshake(self):
        websocket = WebSocket()
        connection = Connection(websocket, delay=60)
        self.start_bridge(connection)
        self.client.requests.put_nowait(b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n')
        await asyncio.wait_for(connection.started.wait(), timeout=0.5)
        await asyncio.wait_for(self.bridge.close(), timeout=0.5)
        self.assertTrue(connection.finished.is_set())
        self.assertTrue(self.client.closed.is_set())
        self.assertEqual(self.bridge.udp_sock.fileno(), -1)

    async def test_handshake_failure_closes_client_without_unhandled_exception(self):
        websocket = WebSocket()
        self.start_bridge(Connection(websocket, error=TimeoutError('synthetic-token')))
        self.client.requests.put_nowait(b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n')
        with self.assertLogs(level='WARNING') as logs:
            await asyncio.wait_for(self.bridge.wait_closed(), timeout=0.5)
        self.assertTrue(self.client.closed.is_set())
        self.assertNotIn('synthetic-token', '\n'.join(logs.output))
        self.assertEqual(self.bridge.udp_sock.fileno(), -1)

    async def test_malformed_packet_logs_failure_location_without_token(self):
        websocket = WebSocket()
        self.start_bridge(Connection(websocket))
        self.client.requests.put_nowait(b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n')
        await asyncio.wait_for(websocket.request_forwarded.wait(), timeout=0.5)
        with self.assertLogs(level='WARNING') as logs:
            websocket.messages.put_nowait(proxy_message(6))
            await asyncio.wait_for(self.bridge.wait_closed(), timeout=0.5)
        output = '\n'.join(logs.output)
        self.assertIn('IndexError', output)
        self.assertIn('parse_rtp_header', output)
        self.assertNotIn('synthetic-token', output)

    async def test_upstream_disconnect_closes_waiting_rtsp_client(self):
        websocket = WebSocket()
        self.start_bridge(Connection(websocket))
        self.client.requests.put_nowait(b'OPTIONS rtsp://synthetic/stream2 RTSP/1.0\r\nCSeq: 1\r\n\r\n')
        await asyncio.wait_for(websocket.request_forwarded.wait(), timeout=0.5)
        with self.assertLogs(level='WARNING'):
            websocket.messages.put_nowait(ConnectionResetError())
            await asyncio.wait_for(self.bridge.wait_closed(), timeout=0.5)
        self.assertTrue(websocket.closed.is_set())
        self.assertTrue(self.client.closed.is_set())

    async def test_channel_setup_timeout_closes_both_sides(self):
        websocket = WebSocket(setup=False)
        self.start_bridge(Connection(websocket))
        self.client.requests.put_nowait(b'OPTIONS rtsp://synthetic/stream2 RTSP/1.0\r\nCSeq: 1\r\n\r\n')
        with patch('kuna_server.CHANNEL_SETUP_TIMEOUT_SECONDS', 0.02):
            with self.assertLogs(level='WARNING'):
                await asyncio.wait_for(self.bridge.wait_closed(), timeout=0.5)
        self.assertTrue(websocket.closed.is_set())
        self.assertTrue(self.client.closed.is_set())

    async def test_channel_setup_retries_twice_on_the_same_websocket(self):
        websocket = WebSocket(setup_after=3)
        self.start_bridge(Connection(websocket))
        self.client.requests.put_nowait(b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n')
        with patch('kuna_server.CHANNEL_SETUP_TIMEOUT_SECONDS', 0.6):
            with patch('kuna_server.CHANNEL_SETUP_RETRY_INTERVAL_SECONDS', 0.1):
                await asyncio.wait_for(websocket.request_forwarded.wait(), timeout=1)
        self.assertEqual(websocket.setup_requests, 3)
        self.connect_mock.assert_called_once()
        self.assertFalse(self.client.closed.is_set())

    async def test_retries_stop_at_the_original_setup_deadline(self):
        websocket = WebSocket(setup=False)
        self.start_bridge(Connection(websocket))
        self.client.requests.put_nowait(b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n')
        with patch('kuna_server.CHANNEL_SETUP_TIMEOUT_SECONDS', 0.15):
            with patch('kuna_server.CHANNEL_SETUP_RETRY_INTERVAL_SECONDS', 0.05):
                with self.assertLogs(level='WARNING'):
                    await asyncio.wait_for(self.bridge.wait_closed(), timeout=0.4)
        self.assertEqual(websocket.setup_requests, 3)
        self.assertTrue(self.client.closed.is_set())
        self.assertTrue(websocket.closed.is_set())

    async def test_successful_setup_does_not_keep_retrying(self):
        websocket = WebSocket()
        self.start_bridge(Connection(websocket))
        self.client.requests.put_nowait(b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n')
        with patch('kuna_server.CHANNEL_SETUP_RETRY_INTERVAL_SECONDS', 0.02):
            await asyncio.wait_for(websocket.request_forwarded.wait(), timeout=0.5)
            await asyncio.sleep(0.06)
        self.assertEqual(websocket.setup_requests, 1)

    async def test_setup_reply_during_token_refresh_prevents_duplicate_request(self):
        websocket = WebSocket(setup=False)

        class TokenProvider:
            token = 'synthetic-token'
            checks = 0

            async def check_token(self):
                self.checks += 1
                if self.checks == 3:  # retry after connect and first setup request
                    websocket.messages.put_nowait(
                        b''.join(n.to_bytes(4, 'big') for n in (8, 0, 0, 0, 0, 7, 0, 0))
                    )
                    for _ in range(3):
                        await asyncio.sleep(0)

        self.start_bridge(Connection(websocket))
        self.bridge.kuna_instance = TokenProvider()
        self.client.requests.put_nowait(b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n')
        with patch('kuna_server.CHANNEL_SETUP_RETRY_INTERVAL_SECONDS', 0.02):
            await asyncio.wait_for(websocket.request_forwarded.wait(), timeout=0.5)
        self.assertEqual(websocket.setup_requests, 1)
        self.assertEqual(self.bridge.kuna_instance.checks, 3)

    async def test_retry_token_refresh_cannot_extend_setup_deadline(self):
        websocket = WebSocket(setup=False)

        class TokenProvider:
            token = 'synthetic-token'
            checks = 0
            retry_cancelled = False

            async def check_token(self):
                self.checks += 1
                if self.checks == 3:
                    try:
                        await asyncio.Event().wait()
                    finally:
                        self.retry_cancelled = True

        self.start_bridge(Connection(websocket))
        provider = self.bridge.kuna_instance = TokenProvider()
        self.client.requests.put_nowait(b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n')
        with patch('kuna_server.CHANNEL_SETUP_TIMEOUT_SECONDS', 0.12):
            with patch('kuna_server.CHANNEL_SETUP_RETRY_INTERVAL_SECONDS', 0.04):
                with self.assertLogs(level='WARNING'):
                    await asyncio.wait_for(self.bridge.wait_closed(), timeout=0.5)
        self.assertTrue(provider.retry_cancelled)
        self.assertTrue(self.client.closed.is_set())
        self.assertTrue(websocket.closed.is_set())

    async def test_proxy_receive_path_preserves_bytes_and_channel_zero(self):
        websocket = WebSocket(channel=0)
        self.start_bridge(Connection(websocket))
        self.client.requests.put_nowait(b'OPTIONS rtsp://synthetic/stream2 RTSP/1.0\r\nCSeq: 1\r\n\r\n')
        await asyncio.wait_for(websocket.request_forwarded.wait(), timeout=0.5)
        chunks = (b'RTSP/1.0 200 ', b'OK\r\n\r\n', b'$\x00', b'\x00\x04\x80\x60\x00\x01', b'$\x01\x00\x04\x80\xc8\x00\x01')
        for chunk in chunks:
            self.client.output_changed.clear()
            websocket.messages.put_nowait(proxy_message(4, chunk, channel=0))
            await asyncio.wait_for(self.client.output_changed.wait(), timeout=0.5)
        self.assertEqual(bytes(self.client.output), b''.join(chunks))

    async def test_client_eof_does_not_open_a_late_websocket(self):
        self.client.requests.put_nowait(b'')
        self.start_bridge()
        await asyncio.wait_for(self.bridge.wait_closed(), timeout=0.5)
        self.connect_mock.assert_not_called()

    async def test_concurrent_close_is_idempotent(self):
        connection = Connection(WebSocket(), delay=60)
        self.start_bridge(connection)
        self.client.requests.put_nowait(b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n')
        await asyncio.wait_for(connection.started.wait(), timeout=0.5)
        await asyncio.wait_for(asyncio.gather(self.bridge.close(), self.bridge.close()), timeout=0.5)
        self.assertTrue(self.client.closed.is_set())

    async def test_idle_client_does_not_open_upstream_session(self):
        self.start_bridge()
        await asyncio.wait_for(self.client.read_started.wait(), timeout=0.5)
        # Let any task created before the first read reach websockets.connect.
        for _ in range(3):
            await asyncio.sleep(0)
        self.connect_mock.assert_not_called()
        self.assertFalse(self.client.closed.is_set())

    async def test_real_websocket_debug_handshake_does_not_log_token(self):
        self.connect.stop()
        received_request = asyncio.Event()

        async def serve_upstream(socket):
            self.assertEqual(await socket.recv(), b'hello')
            await socket.recv()  # synthetic Kuna setup request
            await socket.send(b''.join(n.to_bytes(4, 'big') for n in (8, 0, 0, 0, 0, 7, 0, 0)))
            await socket.recv()  # forwarded RTSP request
            received_request.set()
            await socket.wait_closed()

        server_logger = logging.getLogger('synthetic.websocket.server')
        server_logger.setLevel(logging.INFO)
        async with websockets.serve(serve_upstream, '127.0.0.1', 0, logger=server_logger) as server:
            port = server.sockets[0].getsockname()[1]
            with patch.object(KunaWS, 'ws_url', f'ws://127.0.0.1:{port}/?authtoken='):
                with self.assertLogs(level='DEBUG') as logs:
                    self.start_bridge()
                    self.client.requests.put_nowait(b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n')
                    await asyncio.wait_for(received_request.wait(), timeout=1)
                    await self.bridge.close()
                self.assertNotIn('synthetic-token', '\n'.join(logs.output))


class StalledWriterTests(unittest.IsolatedAsyncioTestCase):
    async def test_close_aborts_transport_when_buffer_cannot_drain(self):
        class Transport:
            closing = False
            aborted = False

            def is_closing(self):
                return self.closing

            def abort(self):
                self.aborted = True

        class Writer:
            transport = Transport()

            def get_extra_info(self, key):
                return ('127.0.0.1', 1234)

            def close(self):
                self.transport.closing = True

            async def wait_closed(self):
                await asyncio.Event().wait()

        writer = Writer()
        client = rtsp_server(None, writer)
        with patch('kuna_server.CLIENT_CLOSE_TIMEOUT_SECONDS', 0.02):
            await asyncio.wait_for(client.close(), timeout=0.5)
        self.assertTrue(writer.transport.aborted)


if __name__ == '__main__':
    unittest.main()

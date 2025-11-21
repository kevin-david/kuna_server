#!/usr/bin/env python3
#KUNA light/camera rtsp server
#Copywrite Nick Waterton 2025 n.waterton@outlook.com

# N Waterton V 1.0.0 20th October 2025: initial release
# N Waterton V 1.0.1 21st October 2025: added -M option for minnimal logging, custom logger added

import json
from random import choices
import string
import ssl, time, sys, socket, re
import argparse
import websockets
import asyncio
import aiohttp
import signal
import logging
from logging.handlers import RotatingFileHandler
import binascii
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

__version__ = "0.1.4"

def parseargs():
    # Add command line argument parsing
    parser = argparse.ArgumentParser(description='Async Kuna Camera RTSP server: V:{}'.format(__version__))
    
    # Get defaults from environment variables
    default_username = os.getenv('KUNA_USERNAME')
    default_password = os.getenv('KUNA_PASSWORD')
    default_port = int(os.getenv('KUNA_PORT') or '4554')
    default_debug = (os.getenv('KUNA_DEBUG') or 'false').lower() == 'true'
    default_minlog = (os.getenv('KUNA_MINLOG') or 'false').lower() == 'true'
    default_log = os.getenv('KUNA_LOG_FILE')
    
    parser.add_argument('username', action="store", type=str, default=default_username, nargs='?',
                       help='username (default: from KUNA_USERNAME env var)')
    parser.add_argument('password', action="store", type=str, default=default_password, nargs='?',
                       help='password (default: from KUNA_PASSWORD env var)')
    parser.add_argument('-p', '--port',action='store',type=int,default=default_port,
                       help='base RTSP server port to listen on (default: %(default)s)')
    parser.add_argument('-L', '--log', default=default_log, help='log file name (default: from KUNA_LOG_FILE env var or None)')
    parser.add_argument('-D','--debug', action='store_true', default=default_debug, 
                       help='Debug mode (default: %(default)s))')
    parser.add_argument('-M','--minlog', action='store_true', default=default_minlog, 
                       help='Minnimum Logging (default: %(default)s))')
    
    args = parser.parse_args()
    
    # Validate that we have credentials either from args or environment
    if not args.username or not args.password:
        parser.error("username and password are required (provide as arguments or set KUNA_USERNAME and KUNA_PASSWORD environment variables)")
    
    return args
    

class KUNA:
    
    API_URL = "https://server.kunasystems.com/api/v1/"
    AUTH_ENDPOINT = "account/auth/"
    CAMERAS_ENDPOINT = "user/cameras/"
    USER_AGENT = "Kuna/2.4.4 (iPhone; iOS 12.1; Scale/3.00)"
    
    def __init__(self, login, password, port):
        self.log = logging.getLogger(self.__class__.__name__)
        self.login = login
        self.password = password
        self.cameras = {}
        self.port = port
        self.token = None
        self.token_time = None  # Track when token was saved
        self._exit = False
        self.servers = []
        self.start = time.time()
        self._add_signals()
        # Use config directory for token storage in addon environment
        config_dir = os.getenv('CONFIG_DIR', '.')
        self.filename = os.path.join(config_dir, 'kuna-server-token.json')
        self.load_token()
        
    def _add_signals(self):
        '''
        setup signals to exit program
        '''
        try:
            def quit():
                asyncio.create_task(self.exit())
            for sig in ['SIGINT', 'SIGTERM']:
                if hasattr(signal, sig):
                    asyncio.get_running_loop().add_signal_handler(getattr(signal, sig), quit)
        except Exception as e:
            self.log.warning('signal error {}'.format(e))
            
    def get_local_ip_address(self):
        """
        Retrieves the local IP address of the machine.
        """
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Connect to an external address (doesn't actually send data)
            # This forces the socket to bind to a local interface and get its IP
            s.connect(("8.8.8.8", 80))  # Google's public DNS server
            local_ip_address = s.getsockname()[0]
            s.close()
            return local_ip_address
        except Exception as e:
            return f"Error getting local IP address: {e}"
            
    async def exit(self):
        self._exit = True
        for server in self.servers:
            server.close()
            await server.wait_closed()

    def load_token(self):
        try:
            with open(self.filename, 'r') as file:
                data = json.load(file)
                token_save_time = data.get('time', time.time())
                age = time.time() - token_save_time
                if age < 86400:   # if token in file is less than 1 day old
                    self.token = data.get('token')
                    self.token_time = token_save_time
                    self.log.info('got token: {}, age: {} mins'.format(self.token, age//60))
                else:
                    self.log.info('Token in file is expired (age: {} mins), will fetch new one'.format(age//60))
        except FileNotFoundError:
            self.log.warning("{} not found.".format(self.filename))
        except json.JSONDecodeError:
            self.log.error("Error: Invalid JSON format in {}".format(self.filename))
        
    def save_token(self):
        if self.token:
            self.token_time = time.time()
            data = {'token':self.token, 'time':self.token_time}
            with open(self.filename, 'w') as json_file:
                json.dump(data, json_file)
                self.log.info('token saved')
                
    async def check_token(self):
        '''
        Check if token exists and is valid. Refresh if missing or expired.
        '''
        # Check if token is expired (older than 1 day)
        if self.token_time:
            age = time.time() - self.token_time
            if age >= 86400:  # Token is 1 day or older
                self.log.info('Token expired (age: {} mins), refreshing...'.format(age//60))
                self.token = None
        
        if not self.token:
            await self.get_token()
        
    async def get_token(self):
        '''
        Get kuna token from API.
        Returns True if successful, False otherwise.
        '''
        body = {"email": self.login, "password": self.password}
        
        try:
            json_data = await self._request('POST', self.AUTH_ENDPOINT, body, retry_on_auth_error=False)
            
            token = json_data.get("token")
            if token:
                self.token = token
                self.log.info('Got new token')
                self.save_token()
                return True
            
            # Extract error message
            error_msg = json_data.get('non_field_errors', [])
            if error_msg:
                error_msg = '; '.join(error_msg)
            else:
                error_msg = json_data.get('error', json_data.get('message', 'Unknown error'))
            
            self.log.error("Failed to get token: {}".format(error_msg))
            return False
            
        except Exception as e:
            self.log.error("Error getting token: {}".format(e))
            return False
        
    async def get_cameras(self):
        '''
        get kuna cameras list from api
        '''
        json_data = await self._request('GET', self.CAMERAS_ENDPOINT)
        if json_data.get('results'):
            self.log.debug(json_data)
            self.cameras = {self.port+idx: {'name': cam['name'], 'id':cam['serial_number']} for idx, cam in enumerate([camera for camera in json_data['results']])}
            self.log.debug(self.cameras)
        else:
            self.log.error("Unable to obtain Kuna camera list: {}".format(json_data))
        
    async def _request(self, method='POST', url=None, body=None, retry_on_auth_error=True):
        '''
        Make API request to Kuna server.
        Returns dict with response data, or dict with error info on failure.
        '''
        if url != self.AUTH_ENDPOINT:
            await self.check_token()
        
        headers = {"User-Agent": self.USER_AGENT, "Content-Type": "application/json"}
        full_url = f"{self.API_URL}{url}"
        if self.token:
            headers["Authorization"] = "Token {}".format(self.token)
        
        self.log.info('{} {}'.format(method, full_url))
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(method, full_url, headers=headers, json=body, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    self.log.debug(f"Status: {resp.status}")
                    
                    if resp.status == 200:
                        return await resp.json()
                    
                    # Get error details
                    try:
                        error_data = await resp.json()
                    except:
                        error_data = {"status": resp.status, "reason": resp.reason}
                    
                    # Handle authentication errors
                    if resp.status in (401, 403):
                        if retry_on_auth_error and url != self.AUTH_ENDPOINT:
                            # Try refreshing token once
                            self.log.warning("Authentication error, refreshing token...")
                            if await self.get_token():
                                return await self._request(method, url, body, retry_on_auth_error=False)
                            else:
                                self.log.error("Failed to refresh token")
                        else:
                            # Clear invalid token
                            if url != self.AUTH_ENDPOINT:
                                self.token = None
                                self.token_time = None
                        self.log.error("Authentication error: {}".format(error_data))
                        return error_data
                    
                    # Other errors
                    self.log.error("API error ({}): {}".format(resp.status, error_data))
                    return error_data
                    
        except asyncio.TimeoutError:
            self.log.error("Request timeout: {} {}".format(method, full_url))
            return {"error": "Request timeout"}
        except aiohttp.ClientError as e:
            self.log.error("Network error: {} {}".format(method, full_url))
            return {"error": str(e)}
        except Exception as e:
            self.log.exception("Unexpected error: {} {}".format(method, full_url))
            return {"error": str(e)}
        
    async def create_server_handler(self, camera, port):
        async def handler(reader, writer):
            '''
            This callback function will be called as a task every time a connection to the server is made
            '''
            await self.check_token()
            if not self.token:
                self.log.error('Cannot create WebSocket connection: token is None after check_token()')
                self.log.error('Root cause: Failed to authenticate. Check your credentials (username/password) and network connectivity.')
                # Close the connection gracefully
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass
                return
            client = rtsp_server(reader, writer)
            self.log.info('New RTSP connection for camera %s from %s', camera, client.peername)
            KunaWS(camera, port=port, token=self.token, client=client, kuna_instance=self)
        return handler
        
    async def start_rtsp_servers(self):
        '''
        One listener per camera for all clients
        '''
        try:
            # Ensure we have a valid token before starting servers
            await self.check_token()
            if not self.token:
                self.log.error("Cannot start RTSP servers: No valid authentication token")
                self.log.error("Root cause: Failed to authenticate with Kuna API. Please check:")
                self.log.error("  1. Username and password are correct")
                self.log.error("  2. Network connectivity to server.kunasystems.com")
                self.log.error("  3. API service is available")
                raise RuntimeError("Authentication failed: Cannot obtain token from Kuna API")
            
            await self.get_cameras()
            for port, camera in self.cameras.items():
                self.log.info("rtsp server starting")
                host = self.get_local_ip_address() or '0.0.0.0'
                self.log.info(f"Client: start listening for camera: {camera['id']} ({camera['name']}) on {host}:{port}")
                server_handler = await self.create_server_handler(camera['id'], port)
                server = await asyncio.start_server(server_handler, host, port)
                self.servers.append(server)
            await asyncio.gather(*[server.serve_forever() for server in  self.servers])
        except asyncio.exceptions.CancelledError:
            pass

class KunaWS:
    
    ws_url = "wss://server.kunasystems.com/ws/rtsp/proxy?authtoken="    #or video.kunasystems.com
    
    def __init__(self, camera, port, token, client, kuna_instance=None):
        self.log = logging.getLogger(self.__class__.__name__+f'[{client.peername}][{camera}]')
        self.debug = self.log.getEffectiveLevel() == logging.DEBUG
        self.camera = camera
        self.port = port
        self.token = token
        self.kuna_instance = kuna_instance  # Reference to KUNA instance for token refresh
        self._exit = False
        self.ws = None
        self.channel_id = None
        self.client = client
        self.unknown_pt = set()
        # Configure expected payload types and mapping to UDP ports (PT -> port)
        self.mapping = {96: None, 98: None}    #video, audio
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.log.info('starting websocket for camera: {}'.format(camera))
        asyncio.create_task(self._handle())
        
    def log_printable(self, txt):
        if txt.replace('\r\n','').isprintable():
            self.log.info(f'{txt}', extra={'reset':True})
            return True
        return False
            
    async def close_client(self):
        self.connection_id = None
        await self.client.close()
            
    async def close(self):
        self._exit = True
        await self.close_client()
        if self.ws:
            await self.ws.close()
            self.ws = None
            
    def setup_udp(self, txt):
        '''
        setup udp ports to send to, if UDP ports are configured in rtsp setup
        '''
        ports = _get_ports(txt)
        if ports:
            if 'track1' in txt:
                self.mapping[96] = ports[0]
                self.log.info('set UDP video port to {}'.format(self.mapping[96]))
            if 'track5' in txt:
                self.mapping[98] = ports[0]
                self.log.info('set UDP audio port to {}'.format(self.mapping[98]))
                
    async def wait_for_channel_id(self):
        '''
        wait for channel id after websocket connects for the first time
        '''
        count = 0
        while self.channel_id is None:
            self.log.info("waiting for channel id")
            await asyncio.sleep(1)
            if (count:=count+1) % 10 == 0 and self.ws:
                # Refresh token before retrying connection request
                if self.kuna_instance:
                    await self.kuna_instance.check_token()
                    self.token = self.kuna_instance.token
                await self.send_connect_req()
            if count > 20:
                self.log.warning('Aborting')
                await self.close()
                return False
            if not self.ws:
                self.log.info("ws closed, closing connection")
                return False
        return True
            
    async def _handle(self):
        '''
        handle client connection
        '''
        while not self._exit:
            if not self.ws:
                asyncio.create_task(self.kuna_ws_connect())
            data = await self.client.read(2048)
            if not data:
                self.log.info(f'Client: connection closed: {self.client.host}:{self.client.tcp_port}')
                await self.close_client()
                break

            # Handle client connection
            try:
                txt = data.decode('utf-8', errors='ignore')
                self.log_printable('received request: {}'.format(txt))
                self.setup_udp(txt)
                if await self.wait_for_channel_id():
                    if self.ws:
                        frame = self.make_frame(self.channel_id, data)
                        self.log.debug('sending to ws: {}'.format(binascii.hexlify(frame).decode('utf-8')))
                        await self.ws.send(frame)
                else:
                    break
            except Exception as e:
                self.log.error(f"Client: error: can't handle request from {self.client.host}: {e}")
                break
        self.log.info('client handler closed')
        await self.close()

    def parse_rtp_header(self, pkt):
        pt = pkt[1] & 0x7F
        seq = int.from_bytes(pkt[2:4], 'big')
        ts  = int.from_bytes(pkt[4:8], 'big')
        ssrc= int.from_bytes(pkt[8:12], 'big')
        marker = (pkt[1] >> 7) & 0x1
        return {'pt': pt, 'seq': seq, 'ts': ts, 'ssrc': ssrc, 'marker': marker}
            
    def decode_data(self, data):
        '''
        data packet has 16 byte header
        4 bytes packet type (type 4 is rtsp, 6 is audio, 7 is setup, 8 is setup response)
        4 bytes channel_id
        4 bytes chennel_id
        4 bytes data size
        decode header and return data up to size minus header
        '''
        packet_type = int.from_bytes( data[:4], byteorder="big")
        self.log.debug(f'Msg type: {packet_type}', extra={'minlog':True})
        match packet_type:
            case 8:
                #setup
                #skip 16 bytes of unknown cookie?
                error_id = int.from_bytes(data[12:16], byteorder="big")
                error_message_length = int.from_bytes(data[16:20], byteorder="big", signed=True)
                error_message = ""
                if error_message_length > 0:
                    error_message = data[20:20+error_message_length].decode("utf-8")
                    self.log.info("Error ID {}, Length {}: {}".format(error_id, error_message_length, error_message))
                    channel_id = None
                    channel_id2 = None
                else:
                    channel_id = int.from_bytes(data[20:24], byteorder="big")
                    self.log.info("Channel ID: {}".format(channel_id))
                    local_port = int.from_bytes(data[24:28], byteorder="big")
                    self.log.info("Local port: {}".format(local_port))
                    # Other channel IDs?
                    channel_id_length = int.from_bytes(data[28:32], byteorder="big")
                    pos =32
                    channel_ids = []
                    if channel_id_length >= 0:
                        for i in range(channel_id_length):
                            channel_ids.append(int.from_bytes( data[pos:pos+4], byteorder="big"))
                            pos += 4
                        self.log.info("Channel IDs: {}".format(channel_ids))
                    channel_id2 = channel_ids
                size = 0
                data = None
            case 6:
                #UDP data
                channel_id = int.from_bytes( data[4:8], byteorder="big", signed=True)
                channel_id2 = int.from_bytes( data[8:12], byteorder="big", signed=True)
                #4 bytes 00 00 00 0d
                size = 0
            case 4 | _:
                #TCP data
                channel_id = int.from_bytes( data[4:8], byteorder="big", signed=True)
                channel_id2 = int.from_bytes( data[8:12], byteorder="big", signed=True)
                size = int.from_bytes( data[12:16], byteorder="big")
                data = data[16:]
        return packet_type, channel_id, channel_id2, size, data
        
    def string_message(self, message):
        if message is None:
            raise ValueError("Cannot encode None message")
        return self.four_bytes(len(message)) + message.encode('utf-8')

    def four_bytes(self, num):
        # make num into 4 bytes
        return (num).to_bytes(4, byteorder="big")
        
    def make_frame(self, channel_id, data):
        '''
        data packet has a 16 byte header.
        4 bytes packet type (type 4 is rtsp, 6 is audio, 7 is setup, 8 is setup response)
        4 bytes channel_id
        4 bytes channel_id
        4 bytes data length
        '''
        header = (self.four_bytes(4)
                 + self.four_bytes(channel_id)
                 + self.four_bytes(channel_id)
                 + self.four_bytes(len(data))
                 )
        return header+data
        
    def send_to_udp(self, data):
        '''
        send video and audio data to udp socket listeners
        '''
        hdr = self.parse_rtp_header(data)
        pt = hdr['pt']
        target_port = self.mapping.get(pt, None)
        if target_port is None:
            # if unknown PT, skip
            self.log.debug("Unknown PT %d found; skipping packet", pt, extra={'logonce':True})
        else:
            # send raw RTP packet to UDP target (client host)
            self.log.debug('Streaming UDP...', extra={'logonce':True})
            self.log.debug("UDP RTP packet info: pt=%d seq=%d ts=%d ssrc=0x%08x -> %s:%d", pt, hdr['seq'], hdr['ts'], hdr['ssrc'], self.client.host, target_port, extra={'logonce':True})
            self.log.debug('sending RTP packet to UDP port: %d (%s)', target_port, 'video' if pt == 96 else 'audio' if pt == 98 else 'unknown', extra={'logonce':True})
            self.udp_sock.sendto(data, (self.client.host, target_port))
            
    async def send_to_tcp(self, data):
        '''
        send video and audio to client as tcp interleaved data
        '''
        hdr = self.parse_rtp_header(data[4:])
        pt = hdr['pt']
        if pt in self.mapping.keys():
            self.log.debug("TCP RTP packet info: pt=%d seq=%d ts=%d ssrc=0x%08x -> %s (%s)", pt, hdr['seq'], hdr['ts'], hdr['ssrc'], self.client.host, 'video' if pt == 96 else 'audio' if pt == 98 else 'unknown', extra={'logonce':True})
            #self.log.info('Raw Data')
            #hexdump(data)
            await self.client.write(data)
        else:
            self.log.debug("Unknown PT %d found; skipping packet", pt, extra={'logonce':True}) 
        
    async def send_connect_req(self):
        '''
        send connection request to ws
        '''
        self.channel_id = None
        if not self.ws:
            self.log.error('no ws')
            return
        # Refresh token if needed
        if self.kuna_instance:
            await self.kuna_instance.check_token()
            self.token = self.kuna_instance.token
        if not self.token:
            self.log.error('Cannot send connect request: token is None')
            return
        header = (
            self.four_bytes(7)  # packet type
            + self.four_bytes(1) # unknown
            + self.string_message(self.camera)  # Camera ID (porch)
            + self.string_message(self.token)  # Auth Token
        )
        self.log.debug('sending connection request for camera:%s with token: %s', self.camera, self.token)
        self.log.debug("Sending header `%s`", header)
        await self.ws.send(header)
        
    async def kuna_ws_connect(self):
        # Refresh token if needed before connecting
        if self.kuna_instance:
            await self.kuna_instance.check_token()
            self.token = self.kuna_instance.token
        if not self.token:
            self.log.error('Cannot connect to WebSocket: token is None')
            return
        ws_url = f"{self.ws_url}{self.token}"
        self.log.info('Connecting to Kuna WS: %s', ws_url)
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        self.channel_id = None
        async with websockets.connect(ws_url, ssl=ssl_context if ws_url.startswith("wss") else None) as self.ws:
            self.log.info('Websocket Connected')
            await self.ws.send(b'hello')
            await self.send_connect_req()
            while not self._exit:
                try:
                    msg = await self.ws.recv()
                    if isinstance(msg, bytes):
                        self.log.debug('received: %d bytes of binary data', len(msg))
                        packet_type, channel_id, channel_id2, size, data = self.decode_data(msg)
                        match packet_type:
                            case 4:     #TCP rdp/rdcp data
                                printable = self.log_printable(data.decode('utf-8', errors='replace'))
                                if self.client and self.channel_id:
                                    if printable:
                                        await self.client.write(data)
                                    else:
                                        await self.send_to_tcp(data)
                                else:
                                    self.log.info('skipping TCP rtp data')
                            case 6:     #UDP rdp Data
                                if self.client and self.channel_id:
                                    self.send_to_udp(data[38:]) #skip 38 byte header
                                else:
                                    self.log.info('skipping UDP rtp data')
                            case 8:     #setup
                                self.channel_id = channel_id
                                if self.channel_id is None:
                                    self.log.warning('closing ws')
                                    break
                            case _:     #unknown packet type
                                self.log_printable(data.decode('utf-8', errors='replace'))
                                    
                                    
                    elif isinstance(msg, str):
                        self.log.info(msg)
                        
                except websockets.exceptions.ConnectionClosedOK:
                    self.log.warning('Websocket closed normally')
                    break
                except asyncio.CancelledError:
                    self.log.info('Websocket connection cancelled')
                    break
                except Exception as e:
                    self.log.exception('WS error: {}'.format(e))
                    break
        self.ws = None
        self.channel_id = None
        self._ws_connect_task = None
    
                    
class rtsp_server:
    def __init__(self, reader, writer):
        self.log = logging.getLogger(self.__class__.__name__)
        self.reader = reader
        self.writer = writer
        peername = writer.get_extra_info('peername')
        self.host = peername[0]
        self.tcp_port = peername[1]
        self.peername=f'{self.host}:{self.tcp_port}'
        self.log.info(f'Client: new connection from {self.peername}')
        self.log = logging.getLogger(self.__class__.__name__+f'[{self.peername}]')
        
    async def read(self, numbytes=2048):
        try:
            if not self.writer.transport.is_closing():
                return await self.reader.read(numbytes)
        except (asyncio.IncompleteReadError, ConnectionResetError, ConnectionAbortedError) as e:
            # Handle client disconnects / resets
            self.log.warning(f"Client disconnected: {e}")
        except Exception as e:
            self.log.exception(f"Unexpected error reading client: {e}")
        await self.close()
        return None

    async def write(self, frame):
        if self.writer.transport.is_closing():
            await self.close()
            return None
        #self.log.info('Sending to client: {}'.format(binascii.hexlify(frame).decode('ascii')))
        #self.log.info('Sending to client (as text): {}'.format(frame.decode('ascii', errors='ignore')))
        self.log.debug('sending {} bytes to client'.format(len(frame)))
        self.writer.write(frame)
        await self.writer.drain()

    async def close(self):
        try:
            if not self.writer.transport.is_closing():
                self.writer.close()
                await self.writer.wait_closed()
        except Exception:
            pass
        
def hexdump(data, length=16):
    """
    Displays binary data in a Wireshark-like hex dump format with ASCII.

    Args:
        data (bytes): The binary data to display.
        length (int): The number of bytes to display per line.
    """
    if not isinstance(data, bytes):
        raise TypeError("Input 'data' must be a bytes object.")

    for i in range(0, len(data), length):
        chunk = data[i:i + length]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        print(f'{i:08x}  {hex_part.ljust(length * 3 - 1)}  {ascii_part}')

def _get_session_id(ask):
    """ Search session ID in rtsp ask
    """
    res = re.match(r'.+?\nSession: *([^;\r\n]+)', ask, re.DOTALL)
    if res:
        return res.group(1).strip()

    return ''.join(choices(string.ascii_lowercase + string.digits, k=9))


def _get_cseq(ask):
    """ Search CSeq in rtsp ask
    """
    res = re.match(r'.+?\r\nCSeq: (\d+)', ask, re.DOTALL)
    if not res:
        raise RuntimeError('invalid incoming CSeq')
    return int(res.group(1))


def _get_user_agent(ask):
    """ Search User-Agent in rtsp ask
        [ -~] means any ASCII character from the space to the tilde
    """
    res = re.match(r'.+?\r\nUser-Agent: ([ -~]+)\r\n', ask, re.DOTALL + re.IGNORECASE)
    if not res:
        return 'unknown user agent'
    return res.group(1)


def _get_ports(ask):
    """ Search port numbers in rtsp ask
    """
    res = re.match(r'.+?\nTransport:[^\n]+client_port=(\d+)-(\d+)', ask, re.DOTALL)
    if not res:
        return []
    return [int(res.group(1)), int(res.group(2))]


def setup_logger(log_file, log_level, log_format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', minlog=False):
    """Set up logging with rotation. If minlog is True, use stdout only and set level to WARNING."""
    # Change root logger level from WARNING (default) to our desired level
    root_logger = logging.getLogger('')
    root_logger.setLevel(log_level)
    
    # Create handler: file with rotation if log_file specified and minlog is False, otherwise stdout
    if log_file and not minlog:
        handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=5
        )
    else:
        handler = logging.StreamHandler()
    
    handler.setLevel(log_level)
    handler.setFormatter(logging.Formatter(log_format))
    root_logger.addHandler(handler)

async def main():
    args = parseargs()
    setup_logger(args.log,
                 logging.DEBUG if args.debug else logging.INFO,
                 '%(asctime)s %(levelname)5.5s %(name)-10s %(funcName)-20s %(message)s',
                 args.minlog)
                 
    log = logging.getLogger('Main')
                 
    log.info("*******************")
    log.info("* Program Started *")
    log.info("*******************")
    
    log.debug('Debug Mode')
    log.info("{} Version: {}".format(sys.argv[0], __version__))
    log.info("Python Version: {}".format(sys.version.replace('\n','')))
    
    k = KUNA(args.username,
             args.password,
             args.port)
             
    await k.start_rtsp_servers()
    
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logging.info('Caught main exception: %s', e)
        sys.exit(1)
    
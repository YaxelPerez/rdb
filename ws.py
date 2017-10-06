import logging
import socketserver
import hashlib
import base64
import struct

from httphelper import HTTPRequest, HTTPResponse, HTTPParseError


class WebSocketFrameParseError(Exception):
    pass


class WebSocketFrame:
    def __init__(self, data=None, **kwargs):
        self.raw_bytes = bytes()

        # "sensible" defaults
        self.FIN = 1
        self.RSV1 = 0
        self.RSV2 = 0
        self.RSV3 = 0
        self.opcode = 1

        self.MASK = 0

        self.extended_payload_length = None
        if data:
            l = len(data)
            if l <= 125:
                self.payload_length = l
            else:
                if l <= 2**16:
                    self.payload_length = 126
                elif l <= 2**64: # a few exabytes
                    self.payload_length = 127
                self.extended_payload_length = l
        else:
            self.payload_length = 0

        self.bytes_left = 0

        self.masking_key = bytes()
        self.masked_payload = bytes()
        if data:
            if isinstance(data, bytes):
                self.data = data
            elif isinstance(data, str):
                self.data = bytes(data, 'utf-8')
        else:
            self.data = bytes()

        self.complete = False

        self.i = 0
        self.j = 0

        self.__dict__.update(kwargs)

    def build(self, byte):
        # I'm not an authority on cybersecurity, but even know that
        # a cleverly constructed WebSocket frame can be used to exploit something
        # I mean, I'm not doing any validation here whatsoever

        # don't put this on the internet
        self.raw_bytes += bytes([byte])

        if self.i == 0:
            self.FIN = (byte & 0b10000000) >> 7
            self.RSV1 = (byte & 0b01000000) >> 6
            self.RSV2 = (byte & 0b00100000) >> 5
            self.RSV3 = (byte & 0b00010000) >> 4
            self.opcode = (byte & 0b00001111)

            self.i = 1
            return

        if self.i == 1:
            self.MASK = (byte & 0b10000000) >> 7
            self.payload_length = (byte & 0b01111111)
            if self.payload_length > 125:
                self.extended_payload_length = bytes()
            else:
                self.bytes_left = self.payload_length
            self.i = 2
            return

        # indices aren't concrete from here on out
        if self.payload_length == 126:
            # next 2 bytes are extended payload length
            if isinstance(self.extended_payload_length, bytes):
                if len(self.extended_payload_length) == 2:
                    self.extended_payload_length = struct.unpack('>H', self.extended_payload_length)[0]
                    self.bytes_left = self.extended_payload_length
                else:
                    self.extended_payload_length += bytes([byte])
                    self.i += 1
                    return

        if self.payload_length == 127:
            # next 8 bytes are extended payload length
            if isinstance(self.extended_payload_length, bytes):
                if len(self.extended_payload_length) == 8:
                    self.extended_payload_length = struct.unpack('>Q', self.extended_payload_length)[0]
                    self.bytes_left = self.extended_payload_length
                else:
                    self.extended_payload_length += bytes([byte])
                    self.i += 1
                    return

        if self.MASK and len(self.masking_key) < 4:
            self.masking_key += bytes([byte])
            self.i += 1
            if len(self.masking_key) == 4 and self.bytes_left == 0:
                self.complete = True
            return

        if self.bytes_left > 0:
            if self.MASK:
                l = self.extended_payload_length or self.payload_length
                self.masked_payload += bytes([byte])
                self.data += bytes([self.masked_payload[l - self.bytes_left] ^ self.masking_key[self.j % 4]])
                self.j += 1
                self.i += 1
                self.bytes_left -= 1

                if self.bytes_left == 0:
                    self.complete = True
            else:
                self.data += bytes([byte])
        else:
            self.complete = True

    def __bytes__(self):
        if not self.raw_bytes:
            self.raw_bytes = bytes([
                self.FIN << 7 | self.RSV1 << 6 | self.RSV2 << 5 | self.RSV3 << 4 | self.opcode,
                self.MASK << 7 | self.payload_length
            ])
            if self.extended_payload_length:
                if self.payload_length == 126:
                    self.raw_bytes += self.extended_payload_length.to_bytes(2, byteorder='big')
                elif self.payload_length == 127:
                    self.raw_bytes += self.extended_payload_length.to_bytes(8, byteorder='big')
            if self.MASK:
                self.raw_bytes += self.masking_key
                self.raw_bytes += self.masked_payload
            else:
                self.raw_bytes += self.data

        return self.raw_bytes

    def __repr__(self):
        if len(self.data) > 20:
            d = str(self.data[0:20]) + '...'
        else:
            d = str(self.data)
        return '<WebSocketFrame{} data={}>'.format(' [FIN]' if self.FIN else '', d)


class BaseWebSocketHandler(socketserver.StreamRequestHandler):
    def on_data(self, data):
        """ To be overridden by parent class things """
        pass

    def handshake(self):
        request = HTTPRequest()

        try:
            while not request.complete:
                raw_data = self.rfile.readline(65537)
                if raw_data:
                    line = str(raw_data, 'iso-8859-1').rstrip('\r\n')
                    # logging.debug('data: %s', line)
                    request.build(line)
        except HTTPParseError as e:
            logging.debug('Rejected handshake request (Could not parse):\n%s', request)
            logging.debug(e)
            self.wfile.write(str(HTTPResponse(400)))
            self.connection_closed = True
            return

        # validate request
        if not (request.headers.get('Upgrade') == 'websocket' and
                request.headers.get('Connection') == 'Upgrade' and
                'Sec-WebSocket-Key' in request.headers.keys()):
            # oh noooo this code isn't DRY I wrote the same 4 lines twice
            logging.debug('Rejected handshake request (Not a websocket handshake):\n%s', request)
            self.wfile.write(bytes(str(HTTPResponse(400)), 'utf-8'))
            self.connection_closed = True
            return
        logging.debug('Accepted handshake request:\n%s', request)

        # now we gotta come up with a response

        # do the hash thing
        m = hashlib.sha1()
        m.update(bytes(request.headers['Sec-WebSocket-Key'] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 'utf-8'))
        ws_accept = base64.b64encode(m.digest()).decode('utf-8')

        response = HTTPResponse(
            101,
            {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Accept': ws_accept
            }
        )

        logging.debug('Replying with:\n%s', str(response))

        self.wfile.write(bytes(str(response), 'utf-8'))

        self.hand_shaken = True
        logging.debug('Handshake completed')

    def do_websocket_stuff(self):
        # naming is hard okay
        frame = WebSocketFrame()
        try:
            while not frame.complete:
                raw_byte = self.rfile.read(1)
                if raw_byte:
                    # logging.debug(bin(raw_byte[0]))
                    frame.build(raw_byte[0])
            if not frame.MASK:
                raise WebSocketFrameParseError('Mask bit not set')

            if frame.opcode == 0x00:
                # continuation frame thing
                if isinstance(self.data, str):
                    self.data += frame.data.decode('utf-8')
                elif isinstance(self.data, bytes):
                    self.data += frame.data
                else:
                    raise WebSocketFrameParseError('Received a continuation frame without any initial data...')
            elif frame.opcode == 0x01:
                # text data
                self.data = frame.data.decode('utf-8')
            elif frame.opcode == 0x02:
                # binary data
                self.data = frame.data
            elif frame.opcode == 0x08:
                # close connection thing
                self.connection_closed = True
                return
            elif frame.opcode == 0x09:
                # ping
                self.wfile.write(WebSocketFrame(opcode=0x0A))
            elif frame.opcode == 0x0A:
                # I never asked for this, client
                # But uh, thanks
                pass
            else:
                raise WebSocketFrameParseError('Invalid opcode')

            if frame.FIN:
                self.on_data(self.data)
                self.data = None

            logging.debug('Received:\n%s', str(frame))
        except WebSocketFrameParseError as e:
            logging.debug('Got a weird frame. Ditching the connection')
            logging.debug(e)

            self.wfile.write(bytes(WebSocketFrame(opcode=0x08)))

            self.connection_closed = True
            return

    def handle(self):
        self.connection_closed = False
        self.hand_shaken = False

        logging.debug('Opening TCP connection with %s:%s', *self.client_address)
        self.data = None
        while not self.connection_closed:
            if self.hand_shaken:
                self.do_websocket_stuff()
            else:
                self.handshake()

        logging.debug('Closing TCP connection with %s:%s', *self.client_address)

if __name__ == "__main__":

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(levelname)s: %(message)s"
    )

    HOST, PORT = '', 8000

    with socketserver.TCPServer((HOST, PORT), BaseWebSocketHandler) as server:
        logging.info('listening on port %d', PORT)
        server.serve_forever(0.1)

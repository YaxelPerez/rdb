# todo: more commands
# todo: breakpoints
# todo: capture stdout and send to client
# todo: capture file output and send to client

import logging
import socketserver
import bdb
import json

import queue
import threading

from ws import WebSocketFrame, BaseWebSocketHandler

class Rdb(bdb.Bdb):
    def __init__(self, input_queue, output_queue, skip=None):
        self.input_queue = input_queue
        self.output_queue = output_queue
        super(Rdb, self).__init__(skip)

    def user_line(self, frame):
        stack = [(f[0].f_code.co_name, f[1]) for f in self.get_stack(frame, None)[0][1:]]
        command = self.input_queue.get() # block until we get something to do

        if command == 'step':
            self.output_queue.put(stack)
            self.output_queue.task_done()
            return

    def user_return(self, frame, return_value):
        self.output_queue.put('DONE')

# the entire debug system relies on sys.trace_call or something like that
# which calls a callback. This makes the program flow really annoying
# so I'm using a separate thread and just passing messages to the debugger
# this also has the added bonus of not slowing down the server(?) while the code
# is running. Probably.
# btw this is my first time ever doing multithreaded work *confetti*

def worker(input_queue, output_queue, code):
    debugger = Rdb(input_queue, output_queue)
    debugger.run(code) # fairly straightforward

# this is still essentially bound by the whole request-response model
# but HTTP is supposed to be stateless so we have to use WebSockets
COMMANDS = [
    'code',
    'step',
    'flush'
]

class RdbWebSocketHandler(BaseWebSocketHandler):
    def setup(self):
        self.input_queue = queue.Queue()
        self.output_queue = queue.Queue()

        self.debug_thread = None

        super(RdbWebSocketHandler, self).setup()

    def on_data(self, data):
        # try to parse json data
        try:
            json_data = json.loads(data)

            command = json_data['command'].lower()
            if not command in COMMANDS:
                raise Exception('invalid command')

            if command == 'code':
                # start a new debugger thread
                self.debug_thread = threading.Thread(target=worker, args=(self.input_queue, self.output_queue, json_data['code']))
                self.debug_thread.start()
            else:
                if not self.debug_thread:
                    # forgivable error (doesn't close connection)
                    self.send_data('error')
                    return
                    # My bug-sense is tingling
                    # If this causes any annoying bugs, just make it non-forgivable like the others

            if command == 'step':
                self.input_queue.put('step')

            self.send_data('ok')

            self.flush_output()

        except Exception as e:
            self.send_data('error')
            self.wfile.write(bytes(WebSocketFrame(opcode=0x08))) # close
            self.connection_closed = True
            return

    def flush_output(self):
        while not self.output_queue.empty():
            output = self.output_queue.get()
            if output == 'DONE':
                self.send_data('done')
            else:
                self.send_data('data', output)

    def send_data(self, status, data=None):
        self.wfile.write(bytes(WebSocketFrame(json.dumps({
            'status': status,
            'data': data
        }))))

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(levelname)s: %(message)s"
    )

    HOST, PORT = '', 8000

    with socketserver.TCPServer((HOST, PORT), RdbWebSocketHandler) as server:
        logging.debug('Listening on port %d', PORT)
        server.serve_forever(0.1)

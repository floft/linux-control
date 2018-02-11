import os
import json
import tornado.gen
import tornado.ioloop
import tornado.websocket
import tornado.httpclient
from tornado.escape import url_escape

class WSClient:
    def __init__(self, url, ping_interval=60, ping_timeout=30):
        self.url = url
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.ioloop = tornado.ioloop.IOLoop.instance()
        self.ws = None
        self.connect()

        # Keep connecting if it dies
        tornado.ioloop.PeriodicCallback(self.keep_alive, 60000, io_loop=self.ioloop).start()

        self.ioloop.start()

    @tornado.gen.coroutine
    def connect(self):
        try:
            self.ws = yield tornado.websocket.websocket_connect(self.url,
                    ping_interval=self.ping_interval, # make sure we're still connected
                    ping_timeout=self.ping_timeout)
        except tornado.httpclient.HTTPError:
            print("HTTP Error")
        else:
            self.run()

    @tornado.gen.coroutine
    def run(self):
        try:
            while True:
                msg = yield self.ws.read_message()

                if msg is None:
                    print("Connection closed")
                    self.ws = None
                    break
                else:
                    msg = json.loads(msg)

                if "error" in msg:
                    print("Error:", msg["error"])
                    break
                elif "query" in msg:
                    print("Query:", msg["query"])
                elif "command" in msg:
                    print("Command:", msg["command"])
                else:
                    print("Unknown message:", msg)
        except KeyboardInterrupt:
            pass

    def keep_alive(self):
        if self.ws is None:
            print("Reconnecting")
            self.connect()

if __name__ == "__main__":
    assert "ID" in os.environ, "Must define ID environment variable"
    assert "TOKEN" in os.environ, "Must define TOKEN"+\
        "environment variable, get from https://wopto.net:42770/linux-control"
    url = "wss://wopto.net:42770/linux-control/con?"+\
            "id="+url_escape(os.environ['ID'])+\
            "&token="+url_escape(os.environ['TOKEN'])

    client = WSClient(url)

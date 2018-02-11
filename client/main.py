import os
import json
import logging
import tornado.gen
import tornado.ioloop
import tornado.websocket
import tornado.httpclient
from tornado.escape import url_escape

class WSClient:
    def __init__(self, url, ping_interval=60, ping_timeout=60*3):
        self.url = url
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.ioloop = tornado.ioloop.IOLoop.instance()
        self.ws = None
        self.connect()

        # Keep connecting if it dies, every 5 minutes
        tornado.ioloop.PeriodicCallback(self.keep_alive, 300000, io_loop=self.ioloop).start()

        self.ioloop.start()

    @tornado.gen.coroutine
    def connect(self):
        try:
            self.ws = yield tornado.websocket.websocket_connect(self.url,
                    ping_interval=self.ping_interval, # make sure we're still connected
                    ping_timeout=self.ping_timeout)
        except tornado.httpclient.HTTPError:
            logging.error("HTTP error - could not connect to websocket")
        else:
            logging.info("Connection opened")
            self.run()

    @tornado.gen.coroutine
    def run(self):
        try:
            while True:
                msg = yield self.ws.read_message()

                if msg is None:
                    logging.info("Connection closed")
                    self.ws = None
                    break
                else:
                    msg = json.loads(msg)

                if "error" in msg:
                    logging.error(msg["error"])
                    break
                elif "query" in msg:
                    value = msg["query"]["value"]
                    x = msg["query"]["x"]
                    result = self.processQuery(value, x)
                    self.ws.write_message(json.dumps({
                        "response": result
                    }))
                elif "command" in msg:
                    command = msg["command"]["command"]
                    x = msg["command"]["x"]
                    url = msg["command"]["url"]
                    result = self.processCommand(command, x, url)
                    self.ws.write_message(json.dumps({
                        "response": result
                    }))
                else:
                    logging.warning("Unknown message: " + str(msg))
        except KeyboardInterrupt:
            pass

    def keep_alive(self):
        if self.ws is None:
            logging.info("Reconnecting")
            self.connect()

    def processQuery(self, value, x):
        msg = "Unknown query"

        if value == "memory":
            pass
        elif value == "disk":
            pass
        elif value == "battery":
            pass
        elif value == "processor":
            pass
        elif value == "open":
            pass
        elif value == "where":
            pass

        return msg

    def processCommand(self, command, x, url):
        msg = "Unknown command"

        if command == "power off":
            pass
        elif command == "sleep":
            pass
        elif command == "lock":
            pass
        elif command == "unlock":
            pass
        elif command == "open":
            pass
        elif command == "close":
            pass
        elif command == "kill":
            pass
        elif command == "locate":
            pass
        elif command == "fetch":
            pass
        elif command == "set volume":
            pass
        elif command == "stop":
            pass
        elif command == "take a picture":
            pass
        elif command == "screenshot":
            pass
        elif command == "download":
            pass
        elif command == "start recording":
            pass
        elif command == "stop recording":
            pass

        return msg

if __name__ == "__main__":
    assert "ID" in os.environ, "Must define ID environment variable"
    assert "TOKEN" in os.environ, "Must define TOKEN"+\
        "environment variable, get from https://wopto.net:42770/linux-control"
    url = "wss://wopto.net:42770/linux-control/con?"+\
            "id="+url_escape(os.environ['ID'])+\
            "&token="+url_escape(os.environ['TOKEN'])

    # For now, show info
    logging.getLogger().setLevel(logging.INFO)

    client = WSClient(url)

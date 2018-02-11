import os
import json
import tornado.gen
import tornado.ioloop
import tornado.websocket
import tornado.httpclient
from tornado.escape import url_escape

@tornado.gen.coroutine
def main():
    assert "ID" in os.environ, "Must define ID environment variable"
    assert "TOKEN" in os.environ, "Must define TOKEN"+\
        "environment variable, get from https://wopto.net:42770/linux-control"

    url = "wss://wopto.net:42770/linux-control/con?"+\
            "id="+url_escape(os.environ['ID'])+\
            "&token="+url_escape(os.environ['TOKEN'])
    conn = yield tornado.websocket.websocket_connect(url)
    while True:
        msg = yield conn.read_message()

        if msg is None:
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

if __name__ == "__main__":
    io_loop = tornado.ioloop.IOLoop.current()
    io_loop.run_sync(main)

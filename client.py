import os
#import urllib.parse
import tornado.gen
import tornado.ioloop
import tornado.websocket
import tornado.httpclient
from tornado.escape import url_escape

@tornado.gen.coroutine
def main():
    assert "EMAIL" in os.environ, "Must define EMAIL environment variable"
    assert "TOKEN" in os.environ, "Must define TOKEN"+\
        "environment variable, get from https://wopto.net:42770/linux-control"

    """
    request = tornado.httpclient.HTTPRequest(
            "wss://wopto.net:42770/linux-control/con",
            method='POST',
            body=urllib.parse.urlencode({'token': os.environ['TOKEN']}))
    conn = yield tornado.websocket.websocket_connect(request)
    """
    url = "wss://wopto.net:42770/linux-control/con?"+\
            "email="+url_escape(os.environ['EMAIL'])+\
            "&token="+url_escape(os.environ['TOKEN'])
    conn = yield tornado.websocket.websocket_connect(url)
    while True:
        yield conn.write_message("Hello there!")
        msg = yield conn.read_message()
        if msg is None: break
        print("Msg: ", msg)

if __name__ == "__main__":
    io_loop = tornado.ioloop.IOLoop.current()
    io_loop.run_sync(main)

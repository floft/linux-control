import os
import ssl
import json
import time
import websocket

class WSClient:
    def __init__(self, url):
        # From: https://github.com/wee-slack/wee-slack/pull/171
        self.sslopt_ca_certs = {}
        if hasattr(ssl, "get_default_verify_paths") and callable(ssl.get_default_verify_paths):
            ssl_defaults = ssl.get_default_verify_paths()
            if ssl_defaults.cafile is not None:
                self.sslopt_ca_certs = {'ca_certs': ssl_defaults.cafile}

        self.ws = websocket.WebSocketApp(url,
                on_message=self.on_message,
                on_error=self.on_error,
                on_close=self.on_close)
        self.ws.on_open = self.on_open

    def run(self):
        try:
            self.ws.run_forever(
                    sslopt=self.sslopt_ca_certs,
                    ping_interval=60,
                    ping_timeout=30)
        except KeyboardInterrupt:
            pass

    def on_open(self, ws):
        print("Opened")

    def on_close(self, ws):
        print("Closed")

    def on_error(self, ws, error):
        print("Error:", error)

    def on_message(self, ws, msg):
        if msg:
            msg = json.loads(msg)

            if "error" in msg:
                print("Error:", msg["error"])
            elif "query" in msg:
                print("Query:", msg["query"])
            elif "command" in msg:
                print("Command:", msg["command"])
            else:
                print("Unknown message:", msg)

if __name__ == "__main__":
    assert "ID" in os.environ, "Must define ID environment variable"
    assert "TOKEN" in os.environ, "Must define TOKEN"+\
        "environment variable, get from https://wopto.net:42770/linux-control"

    url = "wss://wopto.net:42770/linux-control/con?"+\
            "id="+os.environ['ID']+\
            "&token="+os.environ['TOKEN']

    websocket.enableTrace(True)
    client = WSClient(url)
    client.run()

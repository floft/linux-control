import json
import tornado.gen
import tornado.ioloop
import tornado.websocket

from server.base import BaseHandler

class ClientConnection(BaseHandler,
        tornado.websocket.WebSocketHandler):
    ip = None
    userid = None
    computer = None
    close_timeout = None
    pong_timeout = None

    @tornado.gen.coroutine
    def get_current_user(self):
        """
        See if the email/token is valid
        """
        if self.userid and self.computer:
            return self.userid, self.computer
        else:
            userid = self.get_argument('id')
            token = self.get_argument('token')

            # Check that token is in database for this email
            laptop_token, desktop_token = yield self.get_tokens(userid)

            if token == laptop_token:
                self.userid = userid
                self.computer = "laptop"
            elif token == desktop_token:
                self.userid = userid
                self.computer = "desktop"
            else:
                self.userid = None
                self.computer = None
                self.write_message(json.dumps({
                    "error": "Permission Denied"
                }))
                self.close()

            return self.userid, self.computer

    def check_xsrf_cookie(self):
        """
        Disable check since the client won't be sending cookies
        """
        return True

    @tornado.gen.coroutine
    def open(self):
        userid, computer = yield self.get_current_user()

        if userid:
            self.ip = self.getIP()
            self.clients[userid][computer] = self # Note: overwrite previous socket from user
            print("WebSocket opened by", userid, "for", computer, "on", self.ip)
        else:
            print("WebSocket permission denied")

    @tornado.gen.coroutine
    def on_message(self, message):
        userid, computer = yield self.get_current_user()

        if userid:
            print("Got message:", message, "from", userid, "on", computer)
        else:
            print("WebSocket message permission denied")

    def on_close(self):
        found = False

        for userid, computers in self.clients.items():
            for computer, socket in computers.items():
                if socket == self:
                    found = True
                    del self.clients[userid][computer]
                    break

        print("WebSocket closed, did " + ("" if found else "not ") + "find in list of saved sockets")

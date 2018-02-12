import json
import time
import logging
import tornado.gen
import tornado.queues
import tornado.ioloop
import tornado.websocket

from server.base import BaseHandler

class ClientConnection(BaseHandler,
        tornado.websocket.WebSocketHandler):
    ip = None
    userid = None
    computer = None
    messages = tornado.queues.Queue(maxsize=2)

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
            logging.info("WebSocket opened by "+str(userid)+" for "+computer+" on "+self.ip)
        else:
            logging.warning("WebSocket permission denied")

    @tornado.gen.coroutine
    def on_message(self, msg):
        userid, computer = yield self.get_current_user()

        if userid:
            if msg:
                msg = json.loads(msg)
                logging.info("Got message "+str(msg)+" from "+str(userid)+" on "+computer)
                self.messages.put(msg)
        else:
            logging.warning("WebSocket message permission denied")

    def on_close(self):
        found = False

        for userid, computers in self.clients.items():
            for computer, socket in computers.items():
                if socket == self:
                    found = True
                    del self.clients[userid][computer]
                    break

        logging.info("WebSocket closed, did " + ("" if found else "not ") + "find in list of saved sockets")

    #def on_pong(self, data):
    #    logging.info("Got pong")

    @tornado.gen.coroutine
    def wait_response(self):
        """
        Wait for the response for a certain time, if it comes, return it.
        If it doesn't come before the timeout, return None
        """
        response = None
        timeout = time.time() + 2 # wait up to 2 seconds

        try:
            msg = yield self.messages.get(timeout=timeout)
        except tornado.gen.TimeoutError:
            pass
        else:
            if "response" in msg:
                response = msg["response"]

        return response

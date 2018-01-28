import os
import tornado.web
import tornado.auth
import tornado.ioloop
import tornado.options
import tornado.websocket

from tornado.options import define, options

define("port", default=8888, help="run on the given port", type=int)
define("debug", default=False, help="run in debug mode")

class GoogleOAuth2LoginHandler(tornado.web.RequestHandler,
        tornado.auth.GoogleOAuth2Mixin):
    @tornado.gen.coroutine
    def get(self):
        if self.get_argument('code', False):
            access = yield self.get_authenticated_user(
                redirect_uri='https://wopto.net:42770/linux-control/auth/login',
                code=self.get_argument('code'))
            user = yield self.oauth2_request(
                "https://www.googleapis.com/oauth2/v1/userinfo",
                access_token=access["access_token"])
            # Save the user and access token
            self.set_secure_cookie('access_token', access['access_token'])
            self.set_secure_cookie('email', user['email'])
            self.redirect('/linux-control')
        else:
            yield self.authorize_redirect(
                redirect_uri='https://wopto.net:42770/linux-control/auth/login',
                client_id=self.settings['google_oauth']['key'],
                scope=['profile', 'email'],
                response_type='code',
                extra_params={'approval_prompt': 'auto'})

class MainHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie('email')

    @tornado.web.authenticated
    def get(self):
        email = self.get_secure_cookie('email')
        self.write("Logged in as: "+email.decode("utf-8"))

        self.write("""
        <script>
        var ws = new WebSocket("wss://wopto.net:42770/linux-control/con");
        ws.onopen = function() {
           ws.send("Hello, world");
        };
        ws.onmessage = function (evt) {
           alert(evt.data);
        };
        </script>
        """)

class ClientConnection(tornado.websocket.WebSocketHandler):
    def open(self):
        user_id = self.get_secure_cookie('email')
        if not user_id:
            print("WebSocket refused, not authenticated")
            return None
        print("WebSocket opened")

    def on_message(self, message):
        user_id = self.get_secure_cookie('email')
        if not user_id:
            print("WebSocket refused, not authenticated")
            return None

        self.write_message(u"You said: " + message)

    def on_close(self):
        print("WebSocket closed")

def main():
    assert 'COOKIE_SECRET' in os.environ, "Must define COOKIE_SECRET environment variable"
    assert 'OAUTH_CLIENT_ID' in os.environ, "Must define OAUTH_CLIENT_ID environment variable"
    assert 'OAUTH_CLIENT_SECRET' in os.environ, "Must define OAUTH_CLIENT_SECRET environment variable"

    tornado.options.parse_command_line()
    app = tornado.web.Application([
            (r"/linux-control", MainHandler),
            (r"/linux-control/auth/login", GoogleOAuth2LoginHandler),
            (r"/linux-control/con", ClientConnection)
        ],
        cookie_secret=os.environ['COOKIE_SECRET'],
        xsrf_cookies=True,
        google_oauth={
            'key': os.environ['OAUTH_CLIENT_ID'],
            'secret': os.environ['OAUTH_CLIENT_SECRET']
        },
        login_url="/linux-control/auth/login",
        debug=options.debug,
        )
    app.listen(options.port)
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()

import os
import json
import secrets
import string
import tormysql
import traceback
import tornado.web
import tornado.auth
import tornado.ioloop
import tornado.options
import tornado.websocket
import tornado.httpserver

from tornado_http_auth import BasicAuthMixin
from tornado.options import define, options
from pywakeonlan.wakeonlan import send_magic_packet

define("port", default=8888, help="run on the given port", type=int)
define("debug", default=False, help="run in debug mode")
define("mysql_host", default="127.0.0.1", help="database host")
define("mysql_database", default="linuxcontrol", help="database name")
define("mysql_user", default="linuxcontrol", help="database user")
define("mysql_password", default="linuxcontrol", help="database password")

# For DialogFlow
credentials = { os.environ['HTTP_AUTH_USER']: os.environ['HTTP_AUTH_PASS'] }

def genToken(N=30):
    """
    Generate a crypographically secure random string of a certain length for
    use as a token

    From: https://stackoverflow.com/a/23728630/2698494
    """
    return ''.join(secrets.choice(string.ascii_lowercase +
        string.ascii_uppercase + string.digits) for _ in range(N))

class BaseHandler(tornado.web.RequestHandler):
    @property
    def pool(self):
        return self.application.pool

    def get_current_user(self):
        return self.get_secure_cookie('email')

    @tornado.gen.coroutine
    def get_tokens(self, email):
        """
        Get the tokens for this user and if they don't exist, return None
        """
        laptop_token = None
        desktop_token = None

        with (yield self.pool.Connection()) as conn:
            with conn.cursor() as cursor:
                yield cursor.execute("SELECT laptop_token, desktop_token FROM "+\
                        "users WHERE email=%s", (email))
                data = cursor.fetchone()

                if data and len(data) == 2:
                    laptop_token = data[0]
                    desktop_token = data[1]

        return laptop_token, desktop_token


class GoogleOAuth2LoginHandler(BaseHandler,
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

class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_secure_cookie('email')
        self.redirect('/linux-control')

class MainHandler(BaseHandler):
    @tornado.gen.coroutine
    def gen_tokens(self, email):
        """
        Get the tokens for this user and if they don't exist, create them
        """
        laptop_token, desktop_token = yield self.get_tokens(email)

        if not laptop_token and not desktop_token:
            laptop_token = genToken()
            desktop_token = genToken()

            with (yield self.pool.Connection()) as conn:
                try:
                    with conn.cursor() as cursor:
                        yield cursor.execute(
                            "INSERT INTO users(email, laptop_token, desktop_token) "+\
                            "VALUES(%s,%s,%s)", (email, laptop_token, desktop_token))
                except:
                    yield conn.rollback()
                    print("Rolling back DB:", traceback.format_exc())
                else:
                    yield conn.commit()

        return laptop_token, desktop_token

    @tornado.gen.coroutine
    @tornado.web.authenticated
    def get(self):
        email = self.get_secure_cookie('email')
        self.write("<div>Logged in as: "+email.decode("utf-8")+"</div>")

        # Check that this user is in the database and there are tokens for the
        # laptop and desktop computers, if not add the user and tokens
        laptop_token, desktop_token = yield self.gen_tokens(email)

        self.write("<div>Laptop token: "+laptop_token+"</div>")
        self.write("<div>Desktop token: "+desktop_token+"</div>")

        #self.write("""
        #<script>
        #var ws = new WebSocket("wss://wopto.net:42770/linux-control/con");
        #ws.onopen = function() {
        #   ws.send("Hello, world");
        #};
        #ws.onmessage = function (evt) {
        #   alert(evt.data);
        #};
        #</script>
        #""")

class DialogFlowHandler(BasicAuthMixin, BaseHandler):
    def check_xsrf_cookie(self):
        """
        Disable check since the client won't be sending cookies
        """
        return True

    def prepare(self):
        self.get_authenticated_user(check_credentials_func=credentials.get, realm='Protected')

    def get(self):
        self.write("This is meant to be a webhook for DialogFlow")

    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        print(data)

        # Skip if already answered, e.g. saying "Hi!" will be fulfilled by "Small Talk"
        if 'fulfillmentText' in data['queryResult']:
            self.write(json.dumps({}))
            self.set_header("Content-type", "application/json")
            return

        response="Sorry, I'm not sure how to answer that."

        # Determine command/query and respond appropriately
        try:
            intent = data['queryResult']['intent']['displayName']
            params = data['queryResult']['parameters']

            if intent == "Computer Command":
                command = params['Command']
                computer = params['Computer']
                x = params['X']
                url = params['url']

                # Only command we handle is the WOL packet
                if command == "power on":
                    if computer:
                        # TODO this requires
                        #   - using Oauth2 or implicity authentication within Google Assistant, i.e.
                        #     so we know who the user is
                        #   - let them set this MAC in the web interface
                        mac = self.get_wol_mac(email, computer)
                        send_magic_packet(mac, port=9)
                        response = "Woke your "+computer
                else:
                    response = "Will forward command to "+computer
                    # TODO look up websocket for this connection, if it doesn't
                    # exist say computer not online, otherwise forward and wait
                    # for response
                    #
                    # If this takes too long, then immediately respond "Command sent to laptop"
                    # and then do this: https://productforums.google.com/forum/#!topic/dialogflow/HeXqMLQs6ok;context-place=forum/dialogflow
                    # saving context and later returning response or something
            elif intent == "Computer Query":
                value = params['Value']
                x = params['X']
                computer = params['Computer']

                response = "Will forward query to "+computer
                # TODO same as above... forward to computer if online
        except KeyError:
            pass

        #"source": string,
        #"payload": { },
        #"outputContexts": [ { object(Context) } ],
        #"followupEventInput": { object(EventInput) },
        #"fulfillmentMessages": [ { response } ],
        json_response = json.dumps({ "fulfillmentText": response })
        self.write(json_response)
        self.set_header("Content-type", "application/json")

class ClientConnection(BaseHandler,
        tornado.websocket.WebSocketHandler):
    @tornado.gen.coroutine
    def get_current_user(self):
        """
        See if the email/token is valid

        Return the email as the user_id and whether this is for the laptop
        """
        email = self.get_argument('email')
        token = self.get_argument('token')

        # Check that token is in database for this email
        laptop_token, desktop_token = yield self.get_tokens(email)

        if token == laptop_token:
            return email, True
        elif token == desktop_token:
            return email, False
        else:
            self.write_message(u"Permission Denied")
            self.close()
            return None

    def check_xsrf_cookie(self):
        """
        Disable check since the client won't be sending cookies
        """
        return True

    @tornado.gen.coroutine
    def open(self):
        user_id, laptop = yield self.get_current_user()
        print("WebSocket opened by", user_id, "for " + "laptop" if laptop else "desktop")

        # TODO save this?
        # https://stackoverflow.com/questions/21929315/keeping-a-list-of-websocket-connections-in-tornado

    @tornado.gen.coroutine
    def on_message(self, message):
        user_id, laptop = yield self.get_current_user()
        self.write_message(u"You said: " + message + " on your "+"laptop" if laptop else "desktop")

    def on_close(self):
        print("WebSocket closed")

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/linux-control", MainHandler),
            (r"/linux-control/dialogflow", DialogFlowHandler),
            (r"/linux-control/auth/login", GoogleOAuth2LoginHandler),
            (r"/linux-control/auth/logout", LogoutHandler),
            (r"/linux-control/con", ClientConnection)
        ]
        settings = dict(
            cookie_secret=os.environ['COOKIE_SECRET'],
            xsrf_cookies=True,
            google_oauth={
                'key': os.environ['OAUTH_CLIENT_ID'],
                'secret': os.environ['OAUTH_CLIENT_SECRET']
            },
            login_url="/linux-control/auth/login",
            debug=options.debug,
        )
        super(Application, self).__init__(handlers, **settings)

        self.pool = tormysql.ConnectionPool(
            max_connections = 10,
            idle_seconds = 7200,
            wait_connection_timeout = 3,
            host = options.mysql_host,
            user = options.mysql_user,
            passwd = options.mysql_password,
            db = options.mysql_database,
            charset = "utf8"
        )

        self.maybe_create_tables()

    def __del__(self):
        self.pool.close()

    @tornado.gen.coroutine
    def maybe_create_tables(self):
        with (yield self.pool.Connection()) as conn:
            try:
                with conn.cursor() as cursor:
                    yield cursor.execute("""
                    CREATE TABLE IF NOT EXISTS `users` (
                        `id` int(11) NOT NULL AUTO_INCREMENT,
                        `email` varchar(255) COLLATE utf8_bin NOT NULL,
                        `laptop_token` varchar(255) COLLATE utf8_bin NOT NULL,
                        `desktop_token` varchar(255) COLLATE utf8_bin NOT NULL,
                        PRIMARY KEY (`id`),
                        UNIQUE KEY (`email`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin
                    AUTO_INCREMENT=1 ;
                    """)
            except Exception:
                yield conn.rollback()
                print("Rolling back DB:", traceback.format_exc())
            else:
                yield conn.commit()


def main():
    assert 'COOKIE_SECRET' in os.environ, "Must define COOKIE_SECRET environment variable"
    assert 'OAUTH_CLIENT_ID' in os.environ, "Must define OAUTH_CLIENT_ID environment variable"
    assert 'OAUTH_CLIENT_SECRET' in os.environ, "Must define OAUTH_CLIENT_SECRET environment variable"

    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()

import os
import json
import secrets
import string
import tormysql
import pymysql # not async
import pymysql.cursors # not async
import traceback
import tornado.web
import tornado.auth
import tornado.ioloop
import tornado.options
import tornado.websocket
import tornado.httpserver
import oauth2.grant
import oauth2.tokengenerator
import oauth2.store.dbapi.mysql

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

# This OAuth2 provider stuff based on:
# https://gist.github.com/drgarcia1986/5dbd7ce85fb2db74a51b
class OAuth2Handler(tornado.web.RequestHandler):
    def check_xsrf_cookie(self):
        """
        Disable check since Google won't be submitting via a form on my site

        TODO should I do this?
        """
        return True

    # Generator of tokens (with client authentications)
    def initialize(self, controller):
        self.controller = controller

    def post(self):
        response = self._dispatch_request()

        self._map_response(response)

    def _dispatch_request(self):
        request = self.request
        request.post_param = lambda key: json.loads(request.body.decode())[key]

        return self.controller.dispatch(request, environ={})

    def _map_response(self, response):
        for name, value in list(response.headers.items()):
            self.set_header(name, value)

        self.set_status(response.status_code)
        self.write(response.body)


class OAuth2BaseHandler(tornado.web.RequestHandler):
    def initialize(self, controller):
        self.controller = controller

    # authenticate tokens
    def prepare(self):
        try:
            token = self.get_argument('access_token', None)
            if not token:
                auth_header = self.request.headers.get('Authorization', None)
                if not auth_header:
                    raise Exception('This resource need a authorization token')
                token = auth_header[7:]

            key = 'oauth2_{}'.format(token)
            access = self.controller.access_token_store.rs.get(key)
            if access:
                access = json.loads(access.decode())
            else:
                raise Exception('Invalid Token')
            if access['expires_at'] <= int(time.time()):
                raise Exception('expired token')
        except Exception as err:
            self.set_header('Content-Type', 'application/json')
            self.set_status(401)
            self.finish(json.dumps({'error': str(err)}))

class FooHandler(OAuth2BaseHandler):
    def get(self):
        self.finish(json.dumps({'msg': 'This is Foo!'}))

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
        Disable check since DialogFlow logs in via basic HTTP authentication
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

class Connection:
    """
    Let OAuth2 access database asyncronously

    Usage:
    con = Connection(pool)
    cursor = con.cursor()
    cursor.execute(query, params)
    result = cursor.fetchone() # TODO won't work?
    result = cursor.fetchall()
    con.commit()
    cursor.close()

    TODO Doesn't work.... stuff isn't actually executed
    """
    def __init__(self, pool):
        self.pool = pool
        self.isopen = False

    def __del__(self):
        if self.isopen:
            self.cursor.close()
            self.con.close()

    # Deal with returning a result from an async command
    def fetchone(self):
        if self.isopen:
            return self.cursor.fetchone()

        return None

    def fetchall(self):
        if self.isopen:
            return self.cursor.fetchall()

        return None

    # Wrapper for calling the async commands but without returning a future
    def cursor(self):
        #tornado.ioloop.IOLoop.current().spawn_callback(self._cursor())
        self._cursor()
        return self

    def execute(self, query, *params):
        #tornado.ioloop.IOLoop.current().spawn_callback(self._execute, query, *params)
        self._execute(query, *params)

    def commit(self):
        #tornado.ioloop.IOLoop.current().spawn_callback(self._commit)
        self._commit()

    def close(self):
        #tornado.ioloop.IOLoop.current().spawn_callback(self._close)
        self._close()

    # The asynchronous commands
    @tornado.gen.coroutine
    def _cursor(self):
        # If already open, close last cursor
        if self.isopen:
            yield self.cursor.close()

        # Open connection if we don't already have one open
        if not self.isopen:
            self.con = yield self.pool.Connection()

        self.cursor = self.con.cursor()

    @tornado.gen.coroutine
    def _execute(self, query, *params):
        if self.isopen:
            #yield tornado.gen.Task(self.cursor.execute, query, params)
            yield self.cursor.execute(query, params)

    @tornado.gen.coroutine
    def _commit(self):
        if self.isopen:
            yield self.con.commit()

    @tornado.gen.coroutine
    def _close(self):
        if self.isopen:
            yield self.cursor.close()
            yield self.con.close()
            self.isopen = False

class Application(tornado.web.Application):
    def __init__(self):
        #
        # Database
        #
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
        #self.dbcon = Connection(self.pool) # Needed for OAuth2
        # TODO this is bad... not syncronous...
        self.dbcon = pymysql.connect(
            host = options.mysql_host,
            user = options.mysql_user,
            password = options.mysql_password,
            db = options.mysql_database,
            charset = "utf8",
            #cursorclass = pymysql.cursors.DictCursor
        )

        # TODO maybe use tornado.ioloop.IOLoop.current().spawn_callback(self.maybe_create_tables) here?
        self.maybe_create_tables()

        #
        # OAuth2 provider
        #
        client_store = oauth2.store.dbapi.mysql.MysqlClientStore(self.dbcon)
        token_store = oauth2.store.dbapi.mysql.MysqlAccessTokenStore(self.dbcon)

        # Generator of tokens
        token_generator = oauth2.tokengenerator.Uuid4()
        token_generator.expires_in[oauth2.grant.ClientCredentialsGrant.grant_type] = 600 # 10 minutes

        # OAuth2 controller
        self.auth_controller = oauth2.Provider(
            access_token_store=token_store,
            auth_code_store=token_store,
            client_store=client_store,
            token_generator=token_generator
        )
        self.auth_controller.token_path = '/linux-control/oauth/token'

        # Add Client Credentials to OAuth2 controller
        self.auth_controller.add_grant(oauth2.grant.ClientCredentialsGrant())

        #
        # Tornado
        #
        handlers = [
            (r"/linux-control", MainHandler),
            (r"/linux-control/dialogflow", DialogFlowHandler),
            (r"/linux-control/auth/login", GoogleOAuth2LoginHandler),
            (r"/linux-control/auth/logout", LogoutHandler),
            (r"/linux-control/con", ClientConnection),
            (r"/linux-control/oauth/auth", OAuth2SiteAdapter, dict(controller=self.auth_controller)),
            (r"/linux-control/oauth/token", OAuth2Handler, dict(controller=self.auth_controller)),
            (r"/linux-control/foo", FooHandler, dict(controller=self.auth_controller))
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

    def __del__(self):
        self.dbcon.close()
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

                    yield cursor.execute("""
                    CREATE TABLE IF NOT EXISTS `access_tokens` (
                      `id` INT NOT NULL AUTO_INCREMENT COMMENT 'Unique identifier',
                      `client_id` VARCHAR(32) NOT NULL COMMENT 'The identifier of a client. Assuming it is an arbitrary text which is a maximum of 32 characters long.',
                      `grant_type` ENUM('authorization_code', 'implicit', 'password', 'client_credentials', 'refresh_token') NOT NULL COMMENT 'The type of a grant for which a token has been issued.',
                      `token` CHAR(36) NOT NULL COMMENT 'The access token.',
                      `expires_at` TIMESTAMP NULL COMMENT 'The timestamp at which the token expires.',
                      `refresh_token` CHAR(36) NULL COMMENT 'The refresh token.',
                      `refresh_expires_at` TIMESTAMP NULL COMMENT 'The timestamp at which the refresh token expires.',
                      `user_id` INT NULL COMMENT 'The identifier of the user this token belongs to.',
                      PRIMARY KEY (`id`),
                      INDEX `fetch_by_refresh_token` (`refresh_token` ASC),
                      INDEX `fetch_existing_token_of_user` (`client_id` ASC, `grant_type` ASC, `user_id` ASC))
                    ENGINE = InnoDB;
                    """)

                    yield cursor.execute("""
                    CREATE TABLE IF NOT EXISTS `access_token_scopes` (
                      `id` INT NOT NULL AUTO_INCREMENT,
                      `name` VARCHAR(32) NOT NULL COMMENT 'The name of scope.',
                      `access_token_id` INT NOT NULL COMMENT 'The unique identifier of the access token this scope belongs to.',
                      PRIMARY KEY (`id`))
                    ENGINE = InnoDB;
                    """)

                    yield cursor.execute("""
                    CREATE TABLE IF NOT EXISTS `access_token_data` (
                      `id` INT NOT NULL AUTO_INCREMENT,
                      `key` VARCHAR(32) NOT NULL COMMENT 'The key of an entry converted to the key in a Python dict.',
                      `value` VARCHAR(32) NOT NULL COMMENT 'The value of an entry converted to the value in a Python dict.',
                      `access_token_id` INT NOT NULL COMMENT 'The unique identifier of the access token a row  belongs to.',
                      PRIMARY KEY (`id`))
                    ENGINE = InnoDB;
                    """)

                    yield cursor.execute("""
                    CREATE TABLE IF NOT EXISTS `auth_codes` (
                      `id` INT NOT NULL AUTO_INCREMENT,
                      `client_id` VARCHAR(32) NOT NULL COMMENT 'The identifier of a client. Assuming it is an arbitrary text which is a maximum of 32 characters long.',
                      `code` CHAR(36) NOT NULL COMMENT 'The authorisation code.',
                      `expires_at` TIMESTAMP NOT NULL COMMENT 'The timestamp at which the token expires.',
                      `redirect_uri` VARCHAR(128) NULL COMMENT 'The redirect URI send by the client during the request of an authorisation code.',
                      `user_id` INT NULL COMMENT 'The identifier of the user this authorisation code belongs to.',
                      PRIMARY KEY (`id`),
                      INDEX `fetch_code` (`code` ASC))
                    ENGINE = InnoDB;
                    """)

                    yield cursor.execute("""
                    CREATE TABLE IF NOT EXISTS `auth_code_data` (
                      `id` INT NOT NULL AUTO_INCREMENT,
                      `key` VARCHAR(32) NOT NULL COMMENT 'The key of an entry converted to the key in a Python dict.',
                      `value` VARCHAR(32) NOT NULL COMMENT 'The value of an entry converted to the value in a Python dict.',
                      `auth_code_id` INT NOT NULL COMMENT 'The identifier of the authorisation code that this row belongs to.',
                      PRIMARY KEY (`id`))
                    ENGINE = InnoDB;
                    """)

                    yield cursor.execute("""
                    CREATE TABLE IF NOT EXISTS `auth_code_scopes` (
                      `id` INT NOT NULL AUTO_INCREMENT,
                      `name` VARCHAR(32) NOT NULL,
                      `auth_code_id` INT NOT NULL,
                      PRIMARY KEY (`id`))
                    ENGINE = InnoDB;
                    """)

                    yield cursor.execute("""
                    CREATE TABLE IF NOT EXISTS `clients` (
                      `id` INT NOT NULL AUTO_INCREMENT,
                      `identifier` VARCHAR(32) NOT NULL COMMENT 'The identifier of a client.',
                      `secret` VARCHAR(32) NOT NULL COMMENT 'The secret of a client.',
                      PRIMARY KEY (`id`))
                    ENGINE = InnoDB;
                    """)

                    yield cursor.execute("""
                    CREATE TABLE IF NOT EXISTS `client_grants` (
                      `id` INT NOT NULL AUTO_INCREMENT,
                      `name` VARCHAR(32) NOT NULL,
                      `client_id` INT NOT NULL COMMENT 'The id of the client a row belongs to.',
                      PRIMARY KEY (`id`))
                    ENGINE = InnoDB;
                    """)

                    yield cursor.execute("""
                    CREATE TABLE IF NOT EXISTS `client_redirect_uris` (
                      `id` INT NOT NULL AUTO_INCREMENT,
                      `redirect_uri` VARCHAR(128) NOT NULL COMMENT 'A URI of a client.',
                      `client_id` INT NOT NULL COMMENT 'The id of the client a row belongs to.',
                      PRIMARY KEY (`id`))
                    ENGINE = InnoDB;
                    """)

                    yield cursor.execute("""
                    CREATE TABLE IF NOT EXISTS `client_response_types` (
                      `id` INT NOT NULL AUTO_INCREMENT,
                      `response_type` VARCHAR(32) NOT NULL COMMENT 'The response type that a client can use.',
                      `client_id` INT NOT NULL COMMENT 'The id of the client a row belongs to.',
                      PRIMARY KEY (`id`))
                    ENGINE = InnoDB;
                    """)

                    yield cursor.execute(
                        "INSERT IGNORE INTO clients(id, identifier, secret) "+\
                        "VALUES(%s,%s,%s)", (1, "google-assistant", genToken()))
                    yield cursor.execute(
                        "INSERT IGNORE INTO client_grants(id, name, client_id) "+\
                        "VALUES(%s,%s,%s)", (1, oauth2.grant.ClientCredentialsGrant.grant_type, 1))
                    yield cursor.execute(
                        "INSERT IGNORE INTO client_redirect_uris(id, redirect_uri, client_id) "+\
                        "VALUES(%s,%s,%s)", (1, "https://oauth-redirect.googleusercontent.com/r/linux-control", 1))
                    yield cursor.execute(
                        "INSERT IGNORE INTO client_response_types(id, response_type, client_id) "+\
                        "VALUES(%s,%s,%s)", (1, "code", 1))

            except Exception:
                yield conn.rollback()
                print("Rolling back DB:", traceback.format_exc())
            else:
                yield conn.commit()
                print("Done with initial database setup")


def main():
    assert 'COOKIE_SECRET' in os.environ, "Must define COOKIE_SECRET environment variable"
    assert 'OAUTH_CLIENT_ID' in os.environ, "Must define OAUTH_CLIENT_ID environment variable"
    assert 'OAUTH_CLIENT_SECRET' in os.environ, "Must define OAUTH_CLIENT_SECRET environment variable"
    assert 'HTTP_AUTH_USER' in os.environ, "Must define HTTP_AUTH_USER environment variable"
    assert 'HTTP_AUTH_PASS' in os.environ, "Must define HTTP_AUTH_PASS environment variable"

    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()

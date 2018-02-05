import os
import json
import secrets
import string
import tormysql
import pymysql # not async
import pymysql.cursors # not async
import traceback
import tornado.web
import tornado.template
import tornado.auth
import tornado.escape
import tornado.ioloop
import tornado.options
import tornado.websocket
import tornado.httpserver
import oauth2.grant
import oauth2.web.tornado
import oauth2.tokengenerator
import oauth2.store.dbapi.mysql

from tornado_http_auth import BasicAuthMixin
from tornado.options import define, options
from pywakeonlan.wakeonlan import send_magic_packet
from oauth2.web import AuthorizationCodeGrantSiteAdapter

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
        return self.get_secure_cookie('id')

    def render_from_string(self, tmpl, **kwargs):
        """
        From: https://github.com/tornadoweb/tornado/issues/564
        """
        namespace = self.get_template_namespace()
        namespace.update(kwargs)
        return tornado.template.Template(tmpl).generate(**namespace)

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

    @tornado.gen.coroutine
    def get_macs(self, userid):
        """
        Get MAC address for WOL packets
        """
        laptop_mac = None
        desktop_mac = None

        with (yield self.pool.Connection()) as conn:
            with conn.cursor() as cursor:
                yield cursor.execute("SELECT laptop_mac, desktop_mac FROM "+\
                        "users WHERE id=%s", (userid))
                data = cursor.fetchone()

                if data and len(data) == 2:
                    laptop_mac = data[0]
                    desktop_mac = data[1]

        return laptop_mac, desktop_mac

    @tornado.gen.coroutine
    def getUserID(self, email):
        userid = None

        with (yield self.pool.Connection()) as conn:
            with conn.cursor() as cursor:
                yield cursor.execute("SELECT id FROM "+\
                        "users WHERE email=%s", (email))
                data = cursor.fetchone()

                if data and len(data) == 1:
                    userid = data[0]

        return userid

    @tornado.gen.coroutine
    def getUserEmail(self, userid):
        email = None

        with (yield self.pool.Connection()) as conn:
            with conn.cursor() as cursor:
                yield cursor.execute("SELECT email FROM "+\
                        "users WHERE id=%s", (userid))
                data = cursor.fetchone()

                if data and len(data) == 1:
                    email = data[0]

        return email

    @tornado.gen.coroutine
    def getUserIDFromToken(self, token):
        userid = None

        with (yield self.pool.Connection()) as conn:
            with conn.cursor() as cursor:
                yield cursor.execute("SELECT user_id FROM "+\
                        "access_tokens WHERE token=%s", (token))
                data = cursor.fetchone()

                if data and len(data) == 1:
                    userid = data[0]

        return userid

class OAuth2Handler(BaseHandler, oauth2.web.tornado.OAuth2Handler):
    """
    Require the user to be authenticated when going to the authorization page
    """
    TEMPLATE = """
<html>
    <head><title>OAuth2 Authorization</title></head>
    <body>
        <p>Please <a href='/linux-control/auth/login' target='_blank'>Login</a>,
        then <a href='javascript:window.location.reload()'>Reload</a> this page.</p>
    </body>
</html>
    """

    def check_xsrf_cookie(self):
        """
        Only check via our auth form, not when Google gets refresh tokens, etc.

        Note: lazy evaluation means token_path check has to be first
        """
        return self.request.path == self.provider.token_path or \
                super(OAuth2Handler, self).check_xsrf_cookie()

    def get(self):
        # Only require login for auth, not regenerating tokens
        if self.request.path == self.provider.token_path or self.get_current_user():

            # We need to know what user this is to save to the DB along with the tokens
            #if self.request.path == self.provider.authorize_path:
            #    self.user_id = self.get_current_user()

            response = self._dispatch_request()
            self._map_response(response)
        else:
            self.write(self.TEMPLATE)

    def post(self):
        if self.request.path == self.provider.token_path or self.get_current_user():
            response = self._dispatch_request()
            self._map_response(response)
        else:
            self.write(self.TEMPLATE)

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
            userid = yield self.getUserID(user['email'])

            # If not, create the user
            if not userid:
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

                userid = yield self.getUserID(user['email'])

            # If user already in the database, add the ID in our cookie
            # (required for OAuth2 linking to user account for instance)
            self.set_secure_cookie('id', str(userid))

            self.redirect('/linux-control/account')
        else:
            yield self.authorize_redirect(
                redirect_uri='https://wopto.net:42770/linux-control/auth/login',
                client_id=self.settings['google_oauth']['key'],
                scope=['profile', 'email'],
                response_type='code',
                extra_params={'approval_prompt': 'auto'})


class OAuth2SiteAdapter(AuthorizationCodeGrantSiteAdapter):
    """
    This adapter renders a confirmation page so the user can confirm the auth
    request.

    From: http://python-oauth2.readthedocs.io/en/latest/tornado.html
    """

    CONFIRMATION_TEMPLATE = """
<html>
    <head><title>OAuth2 Authorization</title></head>
    <body>
        <p>Do you want to allow Google Assistant access?</p>

        <form method="GET" action="{{ url }}">
            <input type="hidden" name="scope" value="{{ scope }}" />
            <input type="hidden" name="state" value="{{ state }}" />
            <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}" />
            <input type="hidden" name="response_type" value="{{ response_type }}" />
            <input type="hidden" name="client_id" value="{{ client_id }}" />
            <input type="submit" name="confirm" value="Confirm" />
            <input type="submit" name="deny" value="Deny" />
            {% module xsrf_form_html() %}
        </form>
    </body>
</html>
    """
    def render_from_string(self, request, tmpl, **kwargs):
        """
        From: https://github.com/tornadoweb/tornado/issues/564
        """
        namespace = request.handler.get_template_namespace()
        namespace.update(kwargs)
        return tornado.template.Template(tmpl).generate(**namespace)

    def render_auth_page(self, request, response, environ, scopes, client):
        scope = request.get_param("scope")
        state = request.get_param("state")
        redirect_uri = request.get_param("redirect_uri")
        response_type = request.get_param("response_type")
        client_id = request.get_param("client_id")

        if scope:
            scope = tornado.escape.xhtml_escape(scope)
        else:
            scope = ""

        if state:
            state = tornado.escape.xhtml_escape(state)
        else:
            state = ""

        if redirect_uri: 
            redirect_uri = tornado.escape.xhtml_escape(redirect_uri)
        else:
            redirect_uri = ""

        if response_type: 
            response_type = tornado.escape.xhtml_escape(response_type)
        else:
            response_type = ""

        if client_id:
            client_id = tornado.escape.xhtml_escape(client_id)
        else:
            client_id = ""

        response.body = self.render_from_string(request, self.CONFIRMATION_TEMPLATE,
            url=request.path,
            scope=scope,
            state=state,
            redirect_uri=redirect_uri,
            response_type=response_type,
            client_id=client_id)

        return response

    def authenticate(self, request, environ, scopes, client):
        if request.method == "GET":
            if request.get_param("confirm") == "Confirm":
                # Must be a tuple with the second an integer user id
                # https://github.com/wndhydrnt/python-oauth2/blob/3645093f653d5527f83767f8bb5161f9fd03ad83/oauth2/grant.py#L319
                return ({}, request.handler.get_current_user())
        raise oauth2.error.UserNotAuthenticated

    def user_has_denied_access(self, request):
        if request.method == "GET":
            if request.get_param("deny") == "Deny":
                return True
        return False

# https://gist.github.com/drgarcia1986/5dbd7ce85fb2db74a51b
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
        self.clear_cookie('id')
        self.clear_cookie('access_token')
        self.clear_cookie('email')
        self.redirect('/linux-control')

class MainHandler(BaseHandler):
    def get(self):
        userid = self.get_secure_cookie('id')

        # If already logged in, forward to the account page
        if userid: 
            self.redirect("/linux-control/account")
        else:
            self.write("""
<html>
    <head><title>Linux Control</title></head>
    <body>
        <h1>Linux Control</h1>

        <div><a href="/linux-control/auth/login">Login</a></div>
    </body>
</html>
            """)

class AccountHandler(BaseHandler):
    """
        <!--
        <script>
        var ws = new WebSocket("wss://wopto.net:42770/linux-control/con");
        ws.onopen = function() {
           ws.send("Hello, world");
        };
        ws.onmessage = function (evt) {
           alert(evt.data);
        };
        </script>
        -->
    """

    TEMPLATE = """
<html>
    <head><title>Linux Control</title></head>
    <body>
        <h1>Linux Control</h1>
        <div>Logged in as: <i>{{ email }}</i></div>

        <h2>Tokens</h2>
        <div>Laptop token: {{ laptop_token }} (reset)</div>
        <div>Desktop token: {{ desktop_token }} (reset)</div>

        <h2>Wake on LAN</h2>
        <form method="POST">
            Laptop MAC: <input type="text" name="laptop_mac" value="{{ laptop_mac }}" /><br />
            Desktop MAC: <input type="text" name="desktop_mac" value="{{ desktop_mac }}" /><br />
            <input type="submit" value="Save" />
            {% module xsrf_form_html() %}
        </form>

        <div><a href="/linux-control/auth/logout">Logout</a></div>
    </body>
</html>
    """

    @tornado.gen.coroutine
    @tornado.web.authenticated
    def get(self):
        userid = self.get_secure_cookie('id')
        email = self.get_secure_cookie('email')

        # Check that this user is in the database and there are tokens for the
        # laptop and desktop computers
        laptop_token, desktop_token = yield self.get_tokens(email)
        laptop_mac, desktop_mac = yield self.get_macs(userid)

        if laptop_mac:
            laptop_mac = tornado.escape.xhtml_escape(laptop_mac)
        else:
            laptop_mac = ""

        if desktop_mac:
            desktop_mac = tornado.escape.xhtml_escape(desktop_mac)
        else:
            desktop_mac = ""

        self.write(self.render_from_string(self.TEMPLATE,
            email=tornado.escape.xhtml_escape(email.decode("utf-8")),
            laptop_token=laptop_token,
            desktop_token=desktop_token,
            laptop_mac=laptop_mac,
            desktop_mac=desktop_mac,
        ))

    @tornado.gen.coroutine
    @tornado.web.authenticated
    def post(self):
        userid = self.get_current_user()
        laptop_mac = self.get_argument("laptop_mac", "")
        desktop_mac = self.get_argument("desktop_mac", "")

        with (yield self.pool.Connection()) as conn:
            try:
                with conn.cursor() as cursor:
                    yield cursor.execute(
                        "UPDATE users SET laptop_mac = %s, desktop_mac = %s WHERE id = %s",
                        (laptop_mac, desktop_mac, userid))
            except:
                yield conn.rollback()
                print("Rolling back DB:", traceback.format_exc())
            else:
                yield conn.commit()

        self.redirect(self.request.uri)

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

    @tornado.gen.coroutine
    def get_wol_mac(self, userid, computer):
        laptop_mac, desktop_mac = yield self.get_macs(userid)

        if computer.strip().lower() == "laptop":
            return laptop_mac
        else:
            return desktop_mac

    @tornado.gen.coroutine
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        print(data)

        # Skip if already answered, e.g. saying "Hi!" will be fulfilled by "Small Talk"
        if 'fulfillmentText' in data['queryResult']:
            self.write(json.dumps({}))
            self.set_header("Content-type", "application/json")
            return

        # Make sure the user is logged in and provided a valid access token for a signed-up user
        if 'originalDetectIntentRequest' not in data or \
           'payload' not in data['originalDetectIntentRequest'] or \
           'user' not in data['originalDetectIntentRequest']['payload'] or \
           'accessToken' not in data['originalDetectIntentRequest']['payload']['user']:
            self.write(json.dumps({ "fulfillmentText": "You must be logged in." }))
            self.set_header("Content-type", "application/json")
            return

        userid = yield self.getUserIDFromToken(data['originalDetectIntentRequest']['payload']['user']['accessToken'])

        if not userid:
            self.write(json.dumps({ "fulfillmentText": "Invalid access token." }))
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
                        mac = yield self.get_wol_mac(userid, computer)
                        send_magic_packet(mac, port=9)
                        response = "Woke your "+computer
                else:
                    response = "Will forward command to "+computer+" for user "+str(userid)
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

                response = "Will forward query to "+computer+" for user "+str(userid)
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
        userid = yield self.getUserID(email)
        laptop_token, desktop_token = yield self.get_tokens(email)

        if token == laptop_token:
            return userid, email, True
        elif token == desktop_token:
            return userid, email, False
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
        user_id, email, laptop = yield self.get_current_user()
        print("WebSocket opened by", user_id, " (", email, ") for ", "laptop" if laptop else "desktop")

        # TODO save this?
        # https://stackoverflow.com/questions/21929315/keeping-a-list-of-websocket-connections-in-tornado

    @tornado.gen.coroutine
    def on_message(self, message):
        user_id, email, laptop = yield self.get_current_user()
        self.write_message(u"You said: "+ message + " on your "+"laptop" if laptop else "desktop")

    def on_close(self):
        print("WebSocket closed")

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
        auth_code_store = oauth2.store.dbapi.mysql.MysqlAuthCodeStore(self.dbcon)
        token_store = oauth2.store.dbapi.mysql.MysqlAccessTokenStore(self.dbcon)

        # Generator of tokens
        token_generator = oauth2.tokengenerator.Uuid4()
        token_generator.expires_in[oauth2.grant.AuthorizationCodeGrant.grant_type] = 600 # 10 minutes

        # OAuth2 controller
        self.auth_controller = oauth2.Provider(
            access_token_store=token_store,
            auth_code_store=auth_code_store,
            client_store=client_store,
            token_generator=token_generator
        )
        self.auth_controller.authorize_path = '/linux-control/oauth/auth'
        self.auth_controller.token_path = '/linux-control/oauth/token'

        # Add Client Credentials to OAuth2 controller
        self.site_adapter = OAuth2SiteAdapter()
        self.auth_controller.add_grant(oauth2.grant.AuthorizationCodeGrant(site_adapter=self.site_adapter))
        # Add refresh token capability and set expiration time of access tokens to 30 days
        self.auth_controller.add_grant(oauth2.grant.RefreshToken(expires_in=2592000))

        #
        # Tornado
        #
        handlers = [
            (r"/linux-control", MainHandler),
            (r"/linux-control/", MainHandler),
            (r"/linux-control/account", AccountHandler),
            (r"/linux-control/dialogflow", DialogFlowHandler),
            (r"/linux-control/auth/login", GoogleOAuth2LoginHandler),
            (r"/linux-control/auth/logout", LogoutHandler),
            (r"/linux-control/con", ClientConnection),
            (self.auth_controller.authorize_path, OAuth2Handler, dict(provider=self.auth_controller)),
            (self.auth_controller.token_path, OAuth2Handler, dict(provider=self.auth_controller)),
            (r"/linux-control/foo", FooHandler, dict(provider=self.auth_controller))
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
                        `laptop_mac` varchar(255) COLLATE utf8_bin,
                        `desktop_mac` varchar(255) COLLATE utf8_bin,
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

                    # Note: whatever this secret is, you'll have to update the OAuth2 client secret in the Google Console
                    yield cursor.execute(
                        "INSERT IGNORE INTO clients(id, identifier, secret) "+\
                        "VALUES(%s,%s,%s)", (1, "google-assistant", genToken()))
                    yield cursor.execute(
                        "INSERT IGNORE INTO client_grants(id, name, client_id) "+\
                        "VALUES(%s,%s,%s)", (1, oauth2.grant.AuthorizationCodeGrant.grant_type, 1))
                    yield cursor.execute(
                        "INSERT IGNORE INTO client_grants(id, name, client_id) "+\
                        "VALUES(%s,%s,%s)", (2, oauth2.grant.RefreshToken.grant_type, 1))
                    yield cursor.execute(
                        "INSERT IGNORE INTO client_redirect_uris(id, redirect_uri, client_id) "+\
                        "VALUES(%s,%s,%s)", (1, "https://oauth-redirect.googleusercontent.com/r/linux-control", 1))
                    yield cursor.execute(
                        "INSERT IGNORE INTO client_redirect_uris(id, redirect_uri, client_id) "+\
                        "VALUES(%s,%s,%s)", (2, "https://developers.google.com/oauthplayground", 1))
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

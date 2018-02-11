import os
import json
import redis
import secrets
import string
import traceback
import collections
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
import oauth2.store.redisdb

from tornado_http_auth import BasicAuthMixin
from tornado.options import define, options
from pywakeonlan.wakeonlan import send_magic_packet
from oauth2.web import AuthorizationCodeGrantSiteAdapter

define("port", default=8888, help="run on the given port", type=int)
define("debug", default=False, help="run in debug mode")
# For OAuth2 data
define("redis_host", default="127.0.0.1", help="database host")
define("redis_port", default="6379", help="database port")

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

    @property
    def redis(self):
        return self.application.redis

    @property
    def clients(self):
        return self.application.clients

    def get_current_user(self):
        userid = None
        cookie = self.get_secure_cookie("id")

        if cookie:
            userid = cookie.decode("utf-8")

        return userid

    def render_from_string(self, tmpl, **kwargs):
        """
        From: https://github.com/tornadoweb/tornado/issues/564
        """
        namespace = self.get_template_namespace()
        namespace.update(kwargs)
        return tornado.template.Template(tmpl).generate(**namespace)

    @tornado.gen.coroutine
    def get_tokens(self, userid):
        """
        Get the tokens for this user and if they don't exist, return None
        """
        laptop_token = None
        desktop_token = None
        result = self.redis.get("user_"+str(userid))

        if result:
            result = json.loads(result.decode("utf-8"))

            if "laptop_token" in result:
                laptop_token = result["laptop_token"]

            if "desktop_token" in result:
                desktop_token = result["desktop_token"]

        return laptop_token, desktop_token

    @tornado.gen.coroutine
    def get_macs(self, userid):
        """
        Get MAC address for WOL packets
        """
        laptop_mac = None
        desktop_mac = None
        result = self.redis.get("user_"+str(userid))

        if result:
            result = json.loads(result.decode("utf-8"))

            if "laptop_mac" in result:
                laptop_mac = result["laptop_mac"]

            if "desktop_mac" in result:
                desktop_mac = result["desktop_mac"]

        return laptop_mac, desktop_mac

    @tornado.gen.coroutine
    def getUserID(self, email):
        userid = None
        result = self.redis.get("email_"+email)

        if result:
            result = json.loads(result.decode("utf-8"))

            if "id" in result:
                userid = result["id"]

        return userid

    @tornado.gen.coroutine
    def getUserEmail(self, userid):
        email = None
        result = self.redis.get("user_"+str(userid))

        if result:
            result = json.loads(result.decode("utf-8"))

            if "email" in result:
                email = result["email"]

        return email

    @tornado.gen.coroutine
    def getUserIDFromToken(self, token):
        userid = None
        # TODO really should use async redis here or use tornado.gen.Task?
        result = self.redis.get("oauth2_"+token)

        if result:
            result = json.loads(result.decode("utf-8"))

            if "token" in result and "user_id" in result and result["token"] == token:
                userid = result["user_id"]

        return userid

    @tornado.gen.coroutine
    def setMACs(self, userid, laptop_mac, desktop_mac):
        def _setMACs(pipe):
            current = pipe.get("user_"+str(userid))

            if current:
                current = json.loads(current.decode("utf-8"))
                current["laptop_mac"] = laptop_mac
                current["desktop_mac"] = desktop_mac
                pipe.multi()
                pipe.set("user_"+str(userid), json.dumps(current))

        updated = False
        self.redis.transaction(_setMACs, "user_"+str(userid))

        return userid

    @tornado.gen.coroutine
    def resetToken(self, userid, computer):
        def _resetToken(pipe):
            current = pipe.get("user_"+str(userid))

            if current:
                current = json.loads(current.decode("utf-8"))
                current[computer+"_token"] = genToken()
                pipe.multi()
                pipe.set("user_"+str(userid), json.dumps(current))

        updated = False
        self.redis.transaction(_resetToken, "user_"+str(userid))

        return userid

    @tornado.gen.coroutine
    def createUser(self, email):
        """
        Create a new user

        Check that the user doesn't in fact exist before this. Otherwise you'll
        end up with duplicate users.
        """
        # Get user id, set to 0 if it doesn't exist
        userid = self.redis.incr("user_increment")

        print("Userid:", userid)

        # Create user account
        self.redis.set("user_"+str(userid),
            json.dumps({
                "id": userid,
                "email": email,
                "laptop_token": genToken(),
                "desktop_token": genToken(),
                "laptop_mac": "",
                "desktop_mac": ""
            }))

        # Access to user id from email, e.g. for OAuth login via Google
        self.redis.set("email_"+email,
            json.dumps({
                "id": userid
            }))

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
            # Save the user
            userid = yield self.getUserID(user['email'])

            # If not, create the user
            if not userid:
                userid = yield self.createUser(user["email"])

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

class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie('id')
        self.redirect('/linux-control')

class MainHandler(BaseHandler):
    def get(self):
        userid = self.get_current_user()

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
        <div>User ID: {{ userid }}</div>
        <div>Laptop token: {{ laptop_token }} (<a href="?reset=laptop">reset</a>)</div>
        <div>Desktop token: {{ desktop_token }} (<a href="?reset=desktop">reset</a>)</div>

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
        userid = self.get_current_user()
        email = yield self.getUserEmail(userid)

        reset = self.get_argument("reset", "")

        if reset:
            if reset == "laptop":
                yield self.resetToken(userid, reset)
            elif reset == "desktop":
                yield self.resetToken(userid, reset)

            # To get rid of the "?reset=" in the request so we don't keep on
            # reseting it each time you reload the page
            self.redirect(self.request.path)
        else:
            # Check that this user is in the database and there are tokens for the
            # laptop and desktop computers
            laptop_token, desktop_token = yield self.get_tokens(userid)
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
                userid=userid,
                email=tornado.escape.xhtml_escape(email),
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

        yield self.setMACs(userid, laptop_mac, desktop_mac)

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
            print("Error: Invalid access token - userid:", userid, "data:", data)
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

                        if mac:
                            send_magic_packet(mac, port=9)
                            response = "Woke your "+computer
                        else:
                            response = "Your "+computer+" is not set up for wake-on-LAN"
                else:
                    if userid in self.clients and computer in self.clients[userid]:
                        response = "Will forward command to your "+computer
                        self.clients[userid][computer].write_message(json.dumps({
                            "command": { "command": command, "x": x, "url": url }
                        }))
                    else:
                        response = "Your "+computer+" is not currently online"

                    # TODO
                    # If this takes too long, then immediately respond "Command sent to laptop"
                    # and then do this: https://productforums.google.com/forum/#!topic/dialogflow/HeXqMLQs6ok;context-place=forum/dialogflow
                    # saving context and later returning response or something
            elif intent == "Computer Query":
                value = params['Value']
                x = params['X']
                computer = params['Computer']

                if userid in self.clients and computer in self.clients[userid]:
                    response = "Will forward command to your "+computer
                    self.clients[userid][computer].write_message(json.dumps({
                        "query": { "value": value, "x": x }
                    }))
                else:
                    response = "Your "+computer+" is not currently online"
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
        """
        userid = self.get_argument('id')
        token = self.get_argument('token')

        # Check that token is in database for this email
        laptop_token, desktop_token = yield self.get_tokens(userid)

        if token == laptop_token:
            return userid, "laptop"
        elif token == desktop_token:
            return userid, "desktop"
        else:
            self.write_message(json.dumps({
                "error": "Permission Denied"
            }))
            self.close()
            return None, None

    def check_xsrf_cookie(self):
        """
        Disable check since the client won't be sending cookies
        """
        return True

    @tornado.gen.coroutine
    def open(self):
        userid, computer = yield self.get_current_user()

        if userid:
            self.clients[userid][computer] = self # Note: overwrite previous socket from user
            print("WebSocket opened by", userid, "for", computer)
            print("List:", self.clients)
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
        print("List:", self.clients)

class Application(tornado.web.Application):
    def __init__(self):
        #
        # Database
        #
        self.redis = redis.StrictRedis(host=options.redis_host, port=options.redis_port, db=0)

        #
        #
        # Dictionary of dictionaries of open websockets indexed by user id then computer name
        # e.g. { 1: { "laptop": ClientConnection(), "desktop": ClientConnection() ], ... }
        #
        # Recursive: https://stackoverflow.com/a/19189356/2698494
        rec_dd = lambda: collections.defaultdict(rec_dd)
        self.clients = rec_dd()

        #
        # OAuth2 provider
        #
        token_store = oauth2.store.redisdb.TokenStore(
            host=options.redis_host, port=options.redis_port, db=0, prefix="oauth2")
        client_store = oauth2.store.redisdb.ClientStore(
            host=options.redis_host, port=options.redis_port, db=0, prefix="oauth2")

        # Allow Google Assistant to request access
        client_store.add_client(
            client_id=os.environ['OAUTH_GOOGLE_ID'],
            client_secret=os.environ['OAUTH_GOOGLE_SECRET'],
            redirect_uris=[
                os.environ['OAUTH_GOOGLE_URI'],
                "https://developers.google.com/oauthplayground" # For debugging
            ],
            authorized_grants=[
                oauth2.grant.AuthorizationCodeGrant.grant_type,
                oauth2.grant.RefreshToken.grant_type
            ],
            authorized_response_types=["code"]
        )

        # Generator of tokens
        token_generator = oauth2.tokengenerator.Uuid4()

        # OAuth2 controller
        self.auth_controller = oauth2.Provider(
            access_token_store=token_store,
            auth_code_store=token_store,
            client_store=client_store,
            token_generator=token_generator
        )
        self.auth_controller.authorize_path = '/linux-control/oauth/auth'
        self.auth_controller.token_path = '/linux-control/oauth/token'

        # Add Client Credentials to OAuth2 controller
        self.site_adapter = OAuth2SiteAdapter()
        self.auth_controller.add_grant(oauth2.grant.AuthorizationCodeGrant(
            expires_in=86400, site_adapter=self.site_adapter)) # 1 day
        # Add refresh token capability and set expiration time of access tokens to 30 days
        self.auth_controller.add_grant(oauth2.grant.RefreshToken(
            expires_in=2592000, reissue_refresh_tokens=True))

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
            #(r"/linux-control/foo", FooHandler, dict(provider=self.auth_controller))
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

def main():
    assert 'COOKIE_SECRET' in os.environ, "Must define COOKIE_SECRET environment variable"
    assert 'OAUTH_CLIENT_ID' in os.environ, "Must define OAUTH_CLIENT_ID environment variable"
    assert 'OAUTH_CLIENT_SECRET' in os.environ, "Must define OAUTH_CLIENT_SECRET environment variable"
    assert 'OAUTH_GOOGLE_SECRET' in os.environ, "Must define OAUTH_GOOGLE_SECRET environment variable"
    assert 'OAUTH_GOOGLE_URI' in os.environ, "Must define OAUTH_GOOGLE_URI environment variable"
    assert 'HTTP_AUTH_USER' in os.environ, "Must define HTTP_AUTH_USER environment variable"
    assert 'HTTP_AUTH_PASS' in os.environ, "Must define HTTP_AUTH_PASS environment variable"

    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()

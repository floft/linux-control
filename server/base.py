import json
import string
import secrets
import tornado.gen
import tornado.web
import tornado.template

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

    @property
    def gi(self):
        return self.application.gi

    @property
    def serverIp(self):
        return self.application.serverIp

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

    def getIP(self):
        return self.request.headers.get('X-Forwarded-For',
                self.request.headers.get('X-Real-Ip',
                    self.request.remote_ip))

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

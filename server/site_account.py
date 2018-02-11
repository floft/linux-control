import tornado.gen
import tornado.web
import tornado.escape

from server.base import BaseHandler

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

from server.base import BaseHandler

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


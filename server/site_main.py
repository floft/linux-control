from server.base import BaseHandler

class MainHandler(BaseHandler):
    def get(self):
        userid = self.get_current_user()

        # If already logged in, forward to the account page
        if userid:
            self.redirect(self.config["root"]+"/account")
        else:
            self.write("""
<html>
    <head><title>Linux Control</title></head>
    <body>
        <h1>Linux Control</h1>

        <div><a href="{root}/auth/login">Login</a></div>
    </body>
</html>
            """.format(root=self.config["root"]))


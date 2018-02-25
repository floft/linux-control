linux-control
=============
Allows you to setup a server on a computer (e.g. Raspberry Pi) that your Linux
desktop and laptop computers will connect to and then allow some remote
commands to be run via Google Assistant, e.g. power on via Wake-on-LAN, lock or
unlock the screen, put to sleep, open or close a program, etc.

## Summary

Before you start, you need to know how much work this entails:

 * Create Google Actions project ("Google Action Project" section)
 * Setup port forwarding on your router to some internal server
 * Setup Linux Control server on that internal server ("Setup Server" section),
   HTTPS is required
 * On your laptop and/or desktop, setup the Linux Control client ("Setup
   Client" section)

Note: the client code is somewhat messy. For example, locking/unlocking code
probably only works for Gnome at the moment. Opening app code searches Gnome
Tracker database to find .destkop file, then does system call to open with
"dex".

## Google Action Project
Create a new [Google Actions project](https://console.actions.google.com/).

Setup Dialogflow:
 * After naming your Actions project, click on "BUILD" under Dialogflow.
 * Click "Dialogflow V2 API" when Dialogflow opens. Click "CREATE" at the top.
 * Then, click the settings button, the gear icon at the top left.
 * Select the "Export and Import" tab.
 * "Restore from Zip" the *dialogflow/Linux-Control.zip* included in this repo.
 * Click "Fullfillment" tab on the left. Change "example.com:443" to whatever
   your domain and port are.
 * Fill out the BASIC AUTH password to whatever you wish. Then fill in the
   *server/config.yaml* that you'll create in the Server Setup section with
   this same password.

Setup Oauth2:
 * On your Google Actions project, select "Account linking (optional)" and click ADD.
 * Select "Authorization Code". Next.
 * Fill out:
   - Client ID -- e.g. google-assistant
   - Client Secret -- generate with `pwgen 30 1` for example
   - Auth URL -- https://example.com:443/linux-control/oauth/auth
   - Token URL -- https://example.com:443/linux-control/oauth/token
 * Under Server Setup, fill these in as *oauth_google_{id,secret,uri}* in your
   *server/config.yaml* file.

Fill out app information:
 * On your Google Actions project, select "App information" and click EDIT.
 * Fill out name, pronunciation, description, etc.
 * Fill out the invocations, e.g. "Talk to Linux", "Linux Control", "Linux", "Ask Linux", and "Ask Linux Control".

When you are ready to use it (i.e., after you follow the Setup Server section):
 * On Dialogflow, click "Integrations" tab on the left.
 * Click big "Google Assistant".
 * Explicit invocation: Default Welcome Intent.
 * Implicit invocation: Computer Command and Computer Query.
 * Check "Sign in required" on all.
 * Click "TEST".
 * Pull out your phone, linked to your account. Say "Talk to Linux Control."
 * If you've set up the server and everything, it should say that it's not
   linked to your account and give a button to click that'll take you to your
   login page. Click on that. Click "login" when it says to login and then
   reload the page. Link to your Google account. Then click the back button to
   get you back to the login then reload page. Click "reload." Then it should
   be linked to your account.
 * Say something like, "Ask Linux Control where is my laptop"

## Raspberry Pi Setup
For this example, I'll be showing how to set it up on a Raspberry Pi running
Arch Linux. If you already have a computer to use as the server, skip to the
Server Setup section.

### Installing Arch

Follow Arch Linux ARM
[instructions](https://archlinuxarm.org/platforms/armv6/raspberry-pi) for the
Raspberry Pi version you have. I recommend setting up [Google
Authenticator](https://wiki.archlinux.org/index.php/Google_Authenticator) on
the RPi as well if you plan on allowing password logins from the outside world.

    ssh alarm@alarmpi
    su #default password: root
    pacman -S sudo
    groupadd sudo
    useradd -ms /bin/bash -g users -G sudo YOURUSERNAME
    echo '%sudo ALL=(ALL) ALL' >> /etc/sudoers
    passwd
    passwd YOURUSERNAME
    rm /etc/localtime
    ln -s /usr/share/zoneinfo/US/Pacific /etc/localtime
    systemctl enable systemd-resolved
    systemctl start systemd-resolved
    pacman -Syu htop tmux vim libpam-google-authenticator qrencode wol sshguard

Transfer your SSH public key to allow login without password:

    ssh alarmpi 'mkdir -p .ssh; cat >> .ssh/authorized_keys' < .ssh/id_rsa.pub

Interestingly, SSH Guard appears to only work with IPv4, so if you SSH in via
IPv6, then it won't care. Really, doesn't matter since coming in from the
Internet will be IPv4, but you can enable systemd-resolve to get sshing locally
to use IPv4 and then if you want require SSH via only IPv4 with AddressFamily
inet.

Allow installing from the AUR:

    sudo pacman --needed -S base-devel vifm parallel expac devtools aria2 repose

*/etc/pacman.d/custom*:

    [options]
    CacheDir = /var/cache/pacman/pkg
    CacheDir = /var/cache/pacman/custom
    CleanMethod = KeepCurrent

    [custom]
    SigLevel = Optional TrustAll
    Server = file:///var/cache/pacman/custom

Then finish setup, something like this:

    echo "Include = /etc/pacman.d/custom" | sudo tee -a /etc/pacman.conf
    sudo install -d /var/cache/pacman/custom -o $USER
    repo-add /var/cache/pacman/custom/custom.db.tar
    sudo pacman -Syu

    echo "PKGDEST=/var/cache/pacman/custom" | sudo tee -a /etc/makepkg.conf

    mkdir build
    cd build
    curl -o aurutils.tar.gz https://aur.archlinux.org/cgit/aur.git/snapshot/aurutils.tar.gz
    tar xzf aurutils.tar.gz
    cd aurutils
    makepkg -s
    gpg --recv-keys <KEY IT GIVES ERROR FOR>

    sudo pacman -Syu aurutils

## Server Setup
I'll show how to use Nginx with the Linux Control program using Tornado:

### Nginx
Install *nginx*:

    sudo pacman -S python nginx 
    sudo systemctl enable nginx
    sudo systemctl start nginx

Setup HTTPS using Let's Encrypt. In my case, my ISP blocks ports 80 and 443, so
I have to use DNS verification. If this is the case for you too, you might try
[Lego](https://lincolnloop.com/blog/letsencrypt-dns-challenge/). I used the
[Zero SSL](https://zerossl.com/free-ssl/#crt)
website since Namecheap hasn't approved my API access even though I requested
it ages ago and they say give it a few business days.

First time:
 * Enter email
 * Enter domains: example.com www.example.com
 * Check DNS verification

Note, if you use Namecheap, make sure you don't put the "domain.tld" part of
the string. That's implied in the "Host" column of the Advanced DNS entries.

Renewing:
 * Enter email
 * Put in previous key
 * Put in previous CSR

Install certificate:

    sudo mkdir /etc/lets-encrypt

Put the *domain-crt.txt* in *fullchain.pem* and the domain-key.txt in
*/etc/lets-encryptprivkey.pem*.

    sudo chmod 0600 /etc/lets-encrypt
    sudo chown -R root:root /etc/lets-encrypt/

Setup the *nginx.conf* similar to [Tornado's
example](http://www.tornadoweb.org/en/stable/guide/running.html).  Or, look at
the one below similar to what I used, making sure to replace your domain names
and port 9999 with whatever external port you use. I also have a separate
website on the root / and put Linux Control under */linux-control*. If you
change this, then in your *config.yaml* files set *root* to this directory,
making sure to prepend with a / if it's not blank. Note that the
*/linux-control/con* is for the Websocket that the clients will connect to.

    worker_processes 1;

    events {
        worker_connections 1024;
        use epoll;
    }

    http {
        # Enumerate all the Tornado servers here
        upstream frontends {
            server 127.0.0.1:8888;
        }

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        keepalive_timeout 65;
        proxy_read_timeout 200;
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        gzip on;
        gzip_min_length 1000;
        gzip_proxied any;
        gzip_types text/plain text/html text/css text/xml
                   application/x-javascript application/xml
                   application/atom+xml text/javascript;

        # Only retry if there was a communication error, not a timeout
        # on the Tornado server (to avoid propagating "queries of death"
        # to all frontends)
        proxy_next_upstream error;

        server {
            listen 443 ssl default_server;
            listen 9999 ssl default_server;
            server_name domain.tld www.domain.tld;
            ssl_certificate /etc/lets-encrypt/fullchain.pem;
            ssl_certificate_key /etc/lets-encrypt/privkey.pem;

            location / {
                root   /srv/http/www;
                index  index.html index.htm;
            }

            location /linux-control {
                proxy_pass_header Server;
                proxy_set_header Host $http_host;
                proxy_redirect off;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Scheme $scheme;
                proxy_pass http://frontends;
            }

            location /linux-control/con {
                proxy_pass_header Server;
                proxy_set_header Host $http_host;
                proxy_redirect off;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Scheme $scheme;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_pass http://frontends;

                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection "upgrade";
                proxy_read_timeout 600;
            }

            error_page  404              /404.html;
            error_page  500 502 503 504  /50x.html;
            location = /50x.html {
                root   /usr/share/nginx/html;
            }
        }

        # If internal, then port 443 works
        server {
            listen 80;
            server_name localhost;
            return 301 https://$host$request_uri;
        }

        # If connecting from external port 8080, then we're probably not on
        # the local network, so we need to access from external HTTPS port
        server {
            listen 8080; # External HTTP port, if you have it
            server_name localhost;
            return 301 https://$host:9999$request_uri;
        }
    }

Finally, restart *nginx*:

    sudo systemctl restart nginx

### Tornado
Install Tornado and other dependencies of the Linux Control server:

    sudo pacman -S python-tornado python-pip python-redis python-yaml \
        geoip-database-extra python-geoip
    pip install --user tornado-http-auth python-oauth2

    sudo systemctl enable redis
    sudo systemctl start redis

Create a place to put the Linux Control files, e.g. in */srv/http*:

    sudo mkdir /srv/http/linux-control
    sudo chown USER:GROUP /srv/http/linux-control

Copy the server run script and modify the path to the directory:

    cp /srv/http/linux-control/run-server.sh /srv/http/linux-control/run.sh

Service file to start Tornado Linux Control server
*/etc/systemd/system/tornado.service*, making sure to adjust the user and group
to run as:

    [Unit]
    Description=Tornado
    [Service]
    ExecStart=/srv/http/linux-control/run.sh
    User=USER
    Group=GROUP
    [Install]
    WantedBy=multi-user.target

Last of all, copy the example config, edit it, then start tornado:

    cp /srv/http/linux-control/server/config.yaml{.example,}
    # edit /srv/http/linux-control/server/config.yaml
    sudo systemctl start tornado

## Client Setup
Install appropriate dependencies:

    sudo pacman -S python-psutil dexd python-yaml
    aursync python-pulse-control-git
    pip install --user plocate python-libxdo

Then, copy the example config and edit it:

    cp client/config.yaml{.example,}
    # edit client/config.yaml

Make sure you set the server, root, and cookie secret. Get the OAuth2 client
id/secret from Google. Set the OAuth2 provider id/secret to what you gave to
Google in the Google Actions Project instructions earlier. Make sure you set
the URI to point to your project id (see Project ID under the settings of your
Google Actions Project, gear at top left). Set the HTTP BASIC AUTH user/pass
to what you gave Dialogflow earlier.

You'll have to visit your Linux Control website to get the ID and TOKEN that
you'll need for the client. It'll show you your user ID and then a token to
identify your laptop and one to identify your desktop (so it can differentiate
which computer connection is which).

### Client using Graphical Environment
If you're using a graphical environment and want Linux Control to work when you log in, then, first:

    mkdir -p ~/.config/systemd/user/
    cp run-client.sh run.sh

Then edit the path in *run.sh* and create the Systemd service
*~/.config/systemd/user/linux-control.service*:

    [Unit]
    Description=Linux Control
    [Service]
    ExecStart=/path/to/linux-control/run.sh
    Restart=always
    RestartSec=3
    [Install]
    WantedBy=default.target

Make it auto start:

    systemctl --user enable linux-control.service
    systemctl --user start linux-control.service

### Client not using Graphical Environment
At times you may not be using a graphical environment or want Linux Control to
work on boot without having to have the user log in. Then, use this service
file in */etc/systemd/system/linux-control.service* making sure to fill in the
user/group you want to run as:

    [Unit]
    Description=Linux Control
    [Service]
    Environment=DISPLAY=:0
    ExecStart=/path/to/linux-control/run.sh
    Restart=always
    RestartSec=3
    User=USERNAME
    Group=GROUP
    [Install]
    WantedBy=multi-user.target

However, then it won't have permission to reboot, shutdown, etc. unless you
allow it via polkit */etc/polkit-1/rules.d/00-allow-poweroff.rules*
([src](https://gist.github.com/wooptoo/4013294/ccacedd69d54de7f2fd5881b546d5192d6a2bddb)):

    polkit.addRule(function(action, subject) {
        if (action.id.match("org.freedesktop.login1.") && subject.isInGroup("power")) {
            return polkit.Result.YES;
        }
    });

Then make sure you're in the *power* group and enable with:

    sudo systemctl restart polkit
    sudo systemctl enable linux-control
    sudo systemctl restart linux-control

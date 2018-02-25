linux-control
=============
Allows you to setup a server on a computer (e.g. Raspberry Pi) that your Linux
desktop and laptop computers will connect to and then allow some remote
commands to be run via Google Assistant, e.g. power on via Wake-on-LAN, lock or
unlock the screen, put to sleep, open or close a program, etc.

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

Setup HTTPS using Let's Encrypt. I used the [Zero SSL](https://zerossl.com/free-ssl/#crt)
website since Namecheap hasn't approved my API access even though I requested
it ages ago and they say a few business days.

First time:
 * Enter email
 * Enter domains: domain.tld www.domain.tl
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

Setup the *nginx.conf* similar to
[Tornado's example](http://www.tornadoweb.org/en/stable/guide/running.html).
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
    ExecStart=/path/to/linux-control/run-desktop.sh
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

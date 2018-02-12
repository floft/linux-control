import os
import json
import logging
import tornado.gen
import tornado.ioloop
import tornado.websocket
import tornado.httpclient
from tornado.escape import url_escape

# For commands and queries
import time
import dbus
import psutil
import pulsectl

class WSClient:
    def __init__(self, url, ping_interval=60, ping_timeout=60*3):
        self.url = url
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.ioloop = tornado.ioloop.IOLoop.instance()
        self.ws = None
        self.connect()

        # Keep connecting if it dies, every 5 minutes
        tornado.ioloop.PeriodicCallback(self.keep_alive, 300000, io_loop=self.ioloop).start()

        self.ioloop.start()

    @tornado.gen.coroutine
    def connect(self):
        try:
            self.ws = yield tornado.websocket.websocket_connect(self.url,
                    ping_interval=self.ping_interval, # make sure we're still connected
                    ping_timeout=self.ping_timeout)
        except tornado.httpclient.HTTPError:
            logging.error("HTTP error - could not connect to websocket")
        else:
            logging.info("Connection opened")
            self.run()

    @tornado.gen.coroutine
    def run(self):
        try:
            while True:
                msg = yield self.ws.read_message()

                if msg is None:
                    logging.info("Connection closed")
                    self.ws = None
                    break
                else:
                    msg = json.loads(msg)

                if "error" in msg:
                    logging.error(msg["error"])
                    break
                elif "query" in msg:
                    value = msg["query"]["value"]
                    x = msg["query"]["x"]
                    result = self.processQuery(value, x)
                    self.ws.write_message(json.dumps({
                        "response": result
                    }))
                elif "command" in msg:
                    command = msg["command"]["command"]
                    x = msg["command"]["x"]
                    url = msg["command"]["url"]
                    result = self.processCommand(command, x, url)
                    self.ws.write_message(json.dumps({
                        "response": result
                    }))
                else:
                    logging.warning("Unknown message: " + str(msg))
        except KeyboardInterrupt:
            pass

    def keep_alive(self):
        if self.ws is None:
            logging.info("Reconnecting")
            self.connect()

    def processQuery(self, value, x):
        msg = "Unknown query"

        if value == "memory":
            msg = "Memory usage is "+"%.1f"%psutil.virtual_memory().percent+"%"
        elif value == "disk":
            partitions = psutil.disk_partitions()
            msg = "Disk usage is "

            for p in partitions:
                d = psutil.disk_usage(p.mountpoint)
                msg += p.mountpoint + " " + "%.1f"%d.percent + "% "
        elif value == "battery":
            msg = "Battery is "+"%.1f"%psutil.sensors_battery().percent+"%"
        elif value == "processor":
            msg = "CPU usage is "+"%.1f"%psutil.cpu_percent(interval=0.5)+"%"
            pass
        elif value == "open":
            found = False
            search = x.strip().lower()

            for proc in psutil.process_iter(attrs=["name"]):
                if search in proc.info["name"].lower():
                    found = True
                    break

            if found:
                msg = "Yes, "+search+" is running"
            else:
                msg = "No, "+search+" is not running"

        return msg

    def processCommand(self, command, x, url):
        msg = "Unknown command"

        if command == "power off":
            if self.can_poweroff():
                self.ioloop.add_timeout(time.time() + 2, self.cmd_poweroff)
                msg = "Powering off"
            else:
                msg = "Cannot power off"
        elif command == "sleep":
            if self.can_sleep():
                self.ioloop.add_timeout(time.time() + 2, self.cmd_sleep)
                msg = "Sleeping"
            else:
                msg = "Cannot sleep"
        elif command == "reboot":
            if self.can_reboot():
                self.ioloop.add_timeout(time.time() + 2, self.cmd_reboot)
                msg = "Rebooting"
            else:
                msg = "Cannot reboot"
        elif command == "lock":
            self.cmd_lock()
            msg = "Locking"
        elif command == "unlock":
            self.cmd_unlock()
            msg = "Unlocking"
        elif command == "open":
            pass
        elif command == "close":
            pass
        elif command == "kill":
            pass
        elif command == "locate":
            pass
        elif command == "fetch":
            pass
        elif command == "set volume":
            x = x.replace("%", "")

            try:
                volume = int(x)
            except ValueError:
                msg = "Invalid percentage"
            else:
                with pulsectl.Pulse('volume-increaser') as pulse:
                    for sink in pulse.sink_list():
                        pulse.volume_set_all_chans(sink, volume/100.0)
                msg = "Volume set"
        elif command == "stop":
            pass
        elif command == "take a picture":
            pass
        elif command == "screenshot":
            pass
        elif command == "download":
            pass
        elif command == "start recording":
            pass
        elif command == "stop recording":
            pass

        return msg

    def can_poweroff(self):
        bus = dbus.SystemBus()
        obj = bus.get_object('org.freedesktop.login1', '/org/freedesktop/login1')
        iface = dbus.Interface(obj, 'org.freedesktop.login1.Manager')
        result = iface.get_dbus_method("CanPowerOff")
        return result() == "yes"

    def can_sleep(self):
        bus = dbus.SystemBus()
        obj = bus.get_object('org.freedesktop.login1', '/org/freedesktop/login1')
        iface = dbus.Interface(obj, 'org.freedesktop.login1.Manager')
        result = iface.get_dbus_method("CanSuspend")
        return result() == "yes"

    def can_reboot(self):
        bus = dbus.SystemBus()
        obj = bus.get_object('org.freedesktop.login1', '/org/freedesktop/login1')
        iface = dbus.Interface(obj, 'org.freedesktop.login1.Manager')
        result = iface.get_dbus_method("CanReboot")
        return result() == "yes"

    def cmd_poweroff(self):
        bus = dbus.SystemBus()
        obj = bus.get_object('org.freedesktop.login1', '/org/freedesktop/login1')
        iface = dbus.Interface(obj, 'org.freedesktop.login1.Manager')
        method = iface.get_dbus_method("PowerOff")
        method(True)

    def cmd_sleep(self):
        bus = dbus.SystemBus()
        obj = bus.get_object('org.freedesktop.login1', '/org/freedesktop/login1')
        iface = dbus.Interface(obj, 'org.freedesktop.login1.Manager')
        method = iface.get_dbus_method("Suspend")
        method(True)

    def cmd_reboot(self):
        bus = dbus.SystemBus()
        obj = bus.get_object('org.freedesktop.login1', '/org/freedesktop/login1')
        iface = dbus.Interface(obj, 'org.freedesktop.login1.Manager')
        method = iface.get_dbus_method("Reboot")
        method(True)

    def cmd_lock(self):
        bus = dbus.SessionBus()
        obj = bus.get_object('org.gnome.ScreenSaver', '/org/gnome/ScreenSaver')
        iface = dbus.Interface(obj, 'org.gnome.ScreenSaver')
        method = iface.get_dbus_method("SetActive")
        method(True)

    def cmd_unlock(self):
        bus = dbus.SessionBus()
        obj = bus.get_object('org.gnome.ScreenSaver', '/org/gnome/ScreenSaver')
        iface = dbus.Interface(obj, 'org.gnome.ScreenSaver')
        method = iface.get_dbus_method("SetActive")
        method(False)

if __name__ == "__main__":
    assert "ID" in os.environ, "Must define ID environment variable"
    assert "TOKEN" in os.environ, "Must define TOKEN"+\
        "environment variable, get from https://wopto.net:42770/linux-control"
    url = "wss://wopto.net:42770/linux-control/con?"+\
            "id="+url_escape(os.environ['ID'])+\
            "&token="+url_escape(os.environ['TOKEN'])

    # For now, show info
    logging.getLogger().setLevel(logging.INFO)

    client = WSClient(url)

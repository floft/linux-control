import os
import re
import sys
import json
import yaml
import logging
import tornado.gen
import tornado.ioloop
import tornado.websocket
import tornado.httpclient
from tornado.escape import url_escape, url_unescape

import tornado.queues
from tornado.concurrent import run_on_executor
from concurrent.futures import ThreadPoolExecutor

# For commands and queries
import cv2
import dbus
import time
import psutil
import plocate
import pulsectl
import datetime
import subprocess
from xdo import Xdo
from plocate import plocate

import gi
gi.require_version('Tracker', '2.0')
from gi.repository import Tracker

class WSClient:
    def __init__(self, url, ping_interval=60, ping_timeout=60*3, max_workers=4):
        self.url = url
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.ioloop = tornado.ioloop.IOLoop.instance()
        self.ws = None
        self.connect()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

        # Keep track of which files have been found, so you can fetch them
        self.locateResults = {}

        # Keep connecting if it dies, every minute
        tornado.ioloop.PeriodicCallback(self.keep_alive, 60000, io_loop=self.ioloop).start()

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
                result = None
                longResult = None

                msg = yield self.ws.read_message()

                # If closed, break; otherwise, load message JSON data
                if msg is None:
                    logging.info("Connection closed")
                    self.ws = None
                    break
                else:
                    msg = json.loads(msg)

                # Process message
                if "error" in msg:
                    logging.error(msg["error"])
                    break
                elif "query" in msg:
                    value = msg["query"]["value"]
                    x = msg["query"]["x"]
                    result, longResult = yield self.processQuery(value, x)
                elif "command" in msg:
                    command = msg["command"]["command"]
                    x = msg["command"]["x"]
                    url = msg["command"]["url"]
                    number = msg["command"]["number"]
                    result, longResult = yield self.processCommand(command, x, url, number)
                else:
                    logging.warning("Unknown message: " + str(msg))

                # Send results back
                if result and longResult:
                    self.ws.write_message(json.dumps({
                        "response": result,
                        "longResponse": longResult
                    }))
                elif result:
                    self.ws.write_message(json.dumps({
                        "response": result,
                    }))
        except KeyboardInterrupt:
            pass

    def keep_alive(self):
        if self.ws is None:
            logging.info("Reconnecting")
            self.connect()

    @tornado.gen.coroutine
    def processQuery(self, value, x):
        msg = "Unknown query"
        longMsg = None

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

        return msg, longMsg

    @tornado.gen.coroutine
    def processCommand(self, command, x, url, number):
        msg = "Unknown command"
        longMsg = None

        if command == "power off":
            if self.can_poweroff():
                self.ioloop.add_timeout(datetime.timedelta(seconds=3), self.cmd_poweroff)
                msg = "Powering off"
            else:
                msg = "Cannot power off"
        elif command == "sleep":
            if self.can_sleep():
                self.ioloop.add_timeout(datetime.timedelta(seconds=3), self.cmd_sleep)
                msg = "Sleeping"
            else:
                msg = "Cannot sleep"
        elif command == "reboot":
            if self.can_reboot():
                self.ioloop.add_timeout(datetime.timedelta(seconds=3), self.cmd_reboot)
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
            if x:
                results = yield self.cmd_findApp(x.strip().lower())

                if len(results) > 0:
                    fn = results[0][7:] # remove file://
                    name = yield self.getAppName(fn)
                    if name:
                        msg = "Opening "+name
                        longMsg = "Opening "+name+": "+fn
                    else:
                        msg = "Opening"
                        longMsg = "Opening "+fn
                    self.ioloop.add_callback(lambda: self.cmd_openApp(fn, name))
                else:
                    msg = "No results found"
            else:
                msg = "Missing program to start"
        elif command == "close":
            msg = "Not implemented yet"
        elif command == "kill":
            msg = "Not implemented yet"
        elif command == "locate":
            if x:
                # Search might be slow
                try:
                    results = yield tornado.gen.with_timeout(datetime.timedelta(seconds=3.5), self.cmd_locateDB(x))
                except tornado.gen.TimeoutError:
                    msg = "Timed out"
                else:
                    self.locateResults = {}

                    if results:
                        msg = "Found "+str(len(results))+" results"
                        longMsg = "Results:\n"

                        for i, r in enumerate(results):
                            self.locateResults[i+1] = url_unescape(r)
                            longMsg += str(i+1) + ") "+r+"\n"
                    else:
                        msg = "No results found"
            else:
                msg = "Missing search query"

        elif command == "fetch":
            if number:
                try:
                    item = int(re.search(r'\d+', number).group())
                except ValueError:
                    msg = "Invalid item number: "+number
                except AttributeError:
                    msg = "Invalid item number: "+number
                else:
                    if item in self.locateResults:
                        # Input filename, what we saved from the locate command
                        inputFile = self.locateResults[item]

                        # Output filename
                        ext = os.path.splitext(inputFile)[-1]
                        fn = datetime.datetime.now().strftime(
                                "LinuxControl-Fetch-%Y-%m-%d-%Hh-%Mm-%Ss")+ext
                        outputFile = os.path.join(os.environ["HOME"], "Dropbox", fn)

                        msg = "Fetching item "+str(item)
                        longMsg = "Fetching item "+str(item)+": copying"+ \
                            inputFile+" to "+outputFile
                        self.ioloop.add_callback(lambda: self.cmd_fetchFile(
                            inputFile, outputFile))
                    else:
                        msg = "Item not found in last locate results"
            else:
                msg = "Please specify which item of your locate command to fetch."
        elif command == "set volume":
            if number:
                try:
                    volume = int(re.search(r'\d+', number).group())
                except ValueError:
                    msg = "Invalid percentage: "+number
                except AttributeError:
                    msg = "Invalid percentage: "+number
                else:
                    with pulsectl.Pulse('setting-volume') as pulse:
                        for sink in pulse.sink_list():
                            pulse.volume_set_all_chans(sink, volume/100.0)
                    msg = "Volume set"
                    longMsg = "Volume set to "+str(volume)+"%"
            else:
                msg = "Please specify volume percentage"
        elif command == "stop":
            msg = "Not implemented yet"
        elif command == "take a picture":
            filename = os.path.join(os.environ["HOME"], "Dropbox",
                    datetime.datetime.now().strftime(
                        "LinuxControl-Picture-%Y-%m-%d-%Hh-%Mm-%Ss.png"))
            msg = "Taking picture, saving in Dropbox"
            longMsg = "Taking picture: " + filename
            self.ioloop.add_callback(lambda: self.cmd_image(filename))
        elif command == "screenshot":
            filename = os.path.join(os.environ["HOME"], "Dropbox",
                    datetime.datetime.now().strftime(
                        "LinuxControl-Screenshot-%Y-%m-%d-%Hh-%Mm-%Ss.png"))
            msg = "Taking screenshot, saving in Dropbox"
            longMsg = "Taking screenshot: " + filename
            self.ioloop.add_callback(lambda: self.cmd_screenshot(filename))
        elif command == "download":
            msg = "Not implemented yet"
        elif command == "start recording":
            msg = "Not implemented yet"
        elif command == "stop recording":
            msg = "Not implemented yet"

        return msg, longMsg

    @run_on_executor
    def cmd_screenshot(self, filename):
        """
        Take Gnome screenshot
        """
        os.system("gnome-screenshot -f '%s'" % filename)

    @run_on_executor
    def cmd_fetchFile(self, inputFile, outputFile):
        """
        Copy file to Dropbox to make it accessible from phone
        """
        os.symlink(inputFile, outputFile)

    @run_on_executor
    def cmd_image(self, filename):
        """
        Capture image from webcam with OpenCV
        """
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()

        if frame is not None:
            cv2.imwrite(filename, frame)

    @run_on_executor
    def cmd_locate(self, pattern):
        """
        This searches the mlocate DB, but that most of the time times out, so
        instead probably use the cmd_locateDB() function.
        """
        mlocatedb="/var/lib/mlocate/mlocate.db"
        results = ""

        with open(mlocatedb, 'rb') as db:
            for p in plocate.locate([pattern], db,
                    type="file",
                    ignore_case=True,
                    limit=2,
                    existing=False,
                    match="wholename",
                    all=False):
                results += p + " "

        return results

    @run_on_executor
    def cmd_locateDB(self, query):
        """
        Find a file in Gnome Tracker DB
        """
        results = []

        # See: https://github.com/linuxmint/nemo/blob/master/libnemo-private/nemo-search-engine-tracker.c
        conn = Tracker.SparqlConnection.get(None)

        # Match each word in query, split on spaces, case insensitive
        sql = """SELECT nie:url(?urn) WHERE {
            ?urn a nfo:FileDataObject .
            FILTER ("""

        for q in query.lower().split():
            sql += """fn:contains(lcase(nfo:fileName(?urn)),"%s") && """%(q)

        sql += """fn:starts-with(lcase(nie:url(?urn)),"file://"))
        } ORDER BY DESC(nie:url(?urn)) DESC(nfo:fileName(?urn))"""

        cursor = conn.query(sql, None)

        while cursor.next(None):
            results.append(cursor.get_string(0)[0].replace("file://",""))

        return results

    @run_on_executor
    def cmd_findApp(self, query):
        """
        Find desktop file in Gnome Tracker DB
        """
        results = []

        # See: https://github.com/linuxmint/nemo/blob/master/libnemo-private/nemo-search-engine-tracker.c
        conn = Tracker.SparqlConnection.get(None)
        cursor = conn.query("""SELECT nie:url(?urn) WHERE {
            ?urn a nfo:FileDataObject .
            FILTER (fn:contains(lcase(nfo:fileName(?urn)),"%s") &&
                    fn:starts-with(lcase(nie:url(?urn)),"file://") &&
                    fn:ends-with(lcase(nie:url(?urn)),".desktop"))
        } ORDER BY DESC(nie:url(?urn)) DESC(nfo:fileName(?urn))"""%(query), None)

        while cursor.next(None):
            results.append(cursor.get_string(0)[0])

        return results

    @tornado.gen.coroutine
    def getAppName(self, fn):
        """
        Try to get the name of the program from the .desktop file
        """
        name = None

        with open(fn, 'r') as f:
            for line in f:
                m = re.match(r"Name\s?=(.*)$", line)

                if m and len(m.groups()) > 0:
                    name = m.groups()[0]
                    break

        return name

    @run_on_executor
    def cmd_openApp(self, fn, name=None):
        """
        Open desktop file with "dex" command, then try to focus the window
        """
        subprocess.Popen(['dex', fn], close_fds=True)

        if name:
            # Hopefully the app has started by now
            time.sleep(3)

            # Try to bring it to the front
            #
            # Note: we can't use the pid from the Popen since
            # that's the pid of dex, not the program we started
            xdo = Xdo()
            for windowId in xdo.search_windows(winname=name.encode("utf-8")):
                xdo.activate_window(windowId)

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
    # Parse config
    if len(sys.argv) < 2:
        raise RuntimeError("python3 -m client.main config.yaml")

    configFile = sys.argv[1]
    config = {}

    with open(configFile, "r") as f:
        config = yaml.load(f)

    assert "server" in config, "Must define server in config"
    assert "root" in config, "Must define root in config"
    assert "id" in config, "Must define id in config"
    assert "token" in config, "Must define token in config"

    # URL of web socket
    url = "wss://"+config["server"]+config["root"]+"/con?"+\
            "id="+url_escape(str(config["id"]))+\
            "&token="+url_escape(config["token"])

    # For now, show info
    logging.getLogger().setLevel(logging.INFO)

    # Run the client
    client = WSClient(url)

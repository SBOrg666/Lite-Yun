#! /usr/bin/env python3
# -*- coding:utf-8 -*-

import base64
import datetime
import grp
import json
import os
import os.path
import platform
import pwd
import stat
import time
import urllib
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor

import cpuinfo
import psutil
import sh
import tornado.concurrent
import tornado.gen
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.websocket

tornado.options.define("port", default=8000, type=int, help="port")


class indexHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        loggedin = self.get_secure_cookie('login', None)
        return loggedin

    @tornado.web.authenticated
    def get(self):
        self.render('index.html')


class loginHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        self.set_secure_cookie('login', 'admin')
        self.redirect('/')


class cardsHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('cards.html')


class SysteminfoHandler(tornado.websocket.WebSocketHandler):
    def get_current_user(self):
        loggedin = self.get_secure_cookie('login', None)
        return loggedin

    def getRecentMonth(self):
        now = datetime.datetime.now()
        month = now.month
        m = []
        for i in range(6):
            if month > 0:
                m.append(month)
            else:
                m.append(month + 12)
            month -= 1
        m.reverse()
        return m

    def open(self):
        if not self.current_user:
            self.close(code=None, reason='Unauthorized')
        else:
            self.periodic = tornado.ioloop.PeriodicCallback(
                self.sendMessage, 3000)
            self.periodic.start()
            psutil.cpu_percent()
            self.sendMessage()

    def sendMessage(self):
        updata = self.application.upload_data[:]
        updata.append(psutil.net_io_counters().bytes_sent -
                      self.application.initUpload)
        downdata = self.application.download_data[:]
        downdata.append(psutil.net_io_counters().bytes_recv -
                        self.application.initDownload)
        SystemInfo = {'cpu_info': psutil.cpu_percent(percpu=True),
                      'sys_info': [platform.node(), platform.version(), platform.release(), platform.processor(), cpuinfo.get_cpu_info()['hz_advertised'], psutil.virtual_memory().total, datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")],
                      'mem_info': [
            psutil.virtual_memory().used, psutil.virtual_memory().total],
            'swap_info': [psutil.swap_memory().used, psutil.swap_memory().total],
            'disk_info': [(partion.mountpoint, psutil.disk_usage(partion.mountpoint).used, psutil.disk_usage(partion.mountpoint).total) for partion in psutil.disk_partitions()],
            'log_info': '<br>'.join(sh.tail('-n 20', '/var/log/syslog', _iter=True)),
            'network_info': [self.getRecentMonth(), updata, downdata, [data[0] + data[1] for data in zip(updata, downdata)]]}
        self.write_message(SystemInfo)

    def on_message(self, meg):
        pass

    def on_close(self):
        self.periodic.stop()


class forgotpasswdHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('forgot-password.html')


class registerHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('register.html')


class navbarHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('navbar.html')


class processesHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('processes.html')


class downloadHandler(tornado.web.RequestHandler):
    executor = ThreadPoolExecutor()

    def get_current_user(self):
        loggedin = self.get_secure_cookie('login', None)
        return loggedin

    @tornado.concurrent.run_on_executor
    def zipCompress(self, srcItems, desFile):
        def addFile(item, f, prefix):
            if os.path.isdir(item):
                f.write(item, os.path.relpath(item, prefix))
                for i in os.listdir(item):
                    addFile(os.path.join(item, i), f, prefix)
            else:
                f.write(item, os.path.relpath(item, prefix))

        with zipfile.ZipFile(desFile, mode='w') as f:
            for item in srcItems:
                addFile(item, f, os.path.split(item)[0])

    @tornado.gen.coroutine
    @tornado.web.authenticated
    def post(self):
        items = json.loads(self.request.body.decode('utf8'))
        tmpfile = os.path.join(os.path.split(__file__)[
            0], uuid.uuid4().hex + '.zip')
        yield self.zipCompress(items, tmpfile)
        self.write(os.path.split(tmpfile)[1])

    @tornado.gen.coroutine
    @tornado.web.authenticated
    def get(self):
        tmpfile = self.get_argument('name', None)
        if tmpfile:
            tmpfile = os.path.join(os.path.split(__file__)[
                0], urllib.parse.unquote(tmpfile))
            self.set_header('Content-Type', 'application/octet-stream')
            self.set_header('Content-Disposition',
                            'attachment; filename="files.zip"')
            if os.path.exists(tmpfile):
                with open(tmpfile, 'rb') as f:
                    for line in f:
                        yield self.write(line)
                        yield self.flush()
                os.remove(tmpfile)


class uploadHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        loggedin = self.get_secure_cookie('login', None)
        return loggedin

    @tornado.web.authenticated
    def post(self):
        upload_path = self.get_argument('path')
        file_metas = self.request.files['files']
        for meta in file_metas:
            file_name = meta['filename']
            with open(os.path.join(upload_path, file_name), 'wb') as f:
                f.write(meta['body'])
            self.write({'name': os.path.join(upload_path, file_name)})


class pathHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        loggedin = self.get_secure_cookie('login', None)
        return loggedin

    @tornado.web.authenticated
    def get(self, path):

        def getFileInfo(path, dirnames, filenames):
            dirnames.sort()
            filenames.sort()
            if path == '/':
                urlnames = ['/path' + '/' + dirname for dirname in dirnames]
            else:
                urlnames = ['/path' + path + '/' +
                            dirname for dirname in dirnames]    # get urls

            permissions = ([oct(stat.S_IMODE(os.stat(os.path.join(path, dirname)).st_mode))[-3:] for dirname in dirnames], [
                oct(stat.S_IMODE(os.stat(os.path.join(path, filename)).st_mode))[-3:] for filename in filenames])

            sizes = ([os.stat(os.path.join(path, dirname)).st_size for dirname in dirnames], [
                os.stat(os.path.join(path, filename)).st_size for filename in filenames])

            owners = ([pwd.getpwuid(os.stat(os.path.join(path, dirname)).st_uid).pw_name for dirname in dirnames], [
                pwd.getpwuid(os.stat(os.path.join(path, filename)).st_uid).pw_name for filename in filenames])

            groups = ([grp.getgrgid(os.stat(os.path.join(path, dirname)).st_gid).gr_name for dirname in dirnames], [
                grp.getgrgid(os.stat(os.path.join(path, filename)).st_gid).gr_name for filename in filenames])

            mtimes = ([time.asctime(time.localtime(os.stat(os.path.join(path, dirname)).st_mtime)) for dirname in dirnames], [
                time.asctime(time.localtime(os.stat(os.path.join(path, filename)).st_mtime)) for filename in filenames])

            accesses = ([os.access(os.path.join(path, dirname), os.R_OK) for dirname in dirnames], [
                os.access(os.path.join(path, filename), os.R_OK) for filename in filenames])
            return urlnames, permissions, sizes, owners, groups, mtimes, accesses

        path, dirnames, filenames = next(os.walk('/' + path))

        urlnames, permissions, sizes, owners, groups, mtimes, accesses = getFileInfo(
            path, dirnames, filenames)
        self.render('path.html', title="path on server",
                    header='path: ' + path, urlnames=urlnames,
                    dirnames=dirnames, filenames=filenames,
                    permissions=permissions, sizes=sizes,
                    owners=owners, groups=groups, mtimes=mtimes, accesses=accesses, writable=os.access(path, os.W_OK))


class Application(tornado.web.Application):
    def __init__(self):
        cookie_sec = base64.b64encode(uuid.uuid4().bytes)
        handlers = [
            (r'/index.html', tornado.web.RedirectHandler, {'url': '/'}),
            (r'/', indexHandler),
            (r'/login', loginHandler),
            (r'/register.html', registerHandler),
            (r'/cards.html', cardsHandler),
            (r'/Systeminfo', SysteminfoHandler),
            (r'/forgot-password.html', forgotpasswdHandler),
            (r'/navbar.html', navbarHandler),
            (r'/processes.html', processesHandler),
            (r'/download', downloadHandler),
            (r'/upload', uploadHandler),
            (r'/path', tornado.web.RedirectHandler, {'url': '/path/'}),
            (r'/path/(.*)', pathHandler)]

        settings = dict(static_path=os.path.join(
            os.path.dirname(__file__), 'static'), template_path=os.path.join(
            os.path.dirname(__file__), 'template'), debug=True,
            cookie_secret=cookie_sec, xsrf_cookies=True, login_url="/login")

        super().__init__(handlers, **settings)

        self.upload_data = [0, 0, 0, 0, 0]
        self.download_data = [0, 0, 0, 0, 0]
        self.initUpload = psutil.net_io_counters().bytes_sent
        self.initDownload = psutil.net_io_counters().bytes_recv
        tornado.ioloop.IOLoop.current().call_at(
            self.makeDate(), self.updateNetworkData)

    def updateNetworkData(self):
        self.upload_data.pop()
        self.upload_data.append(
            psutil.net_io_counters().bytes_sent - self.initUpload)
        self.download_data.pop()
        self.download_data.append(
            psutil.net_io_counters().bytes_recv - self.initDownload)
        self.initUpload = psutil.net_io_counters().bytes_sent
        self.initDownload = psutil.net_io_counters().bytes_recv
        tornado.ioloop.IOLoop.current().call_at(
            self.makeDate(), self.updateNetworkData)

    def makeDate(self):
        now = datetime.datetime.now()
        year = now.year
        month = now.month
        if month == 12:
            year += 1
            month = 1
        else:
            month += 1

        d = '.'.join([str(1), str(month), str(year)])
        t = '00:00:00'
        date_time = d + ' ' + t
        epoch = time.mktime(time.strptime(date_time, r"%d.%m.%Y %H:%M:%S"))
        return epoch


if __name__ == '__main__':
    tornado.options.parse_command_line()
    app = Application()
    server = tornado.httpserver.HTTPServer(app)
    app.listen(tornado.options.options.port)
    tornado.ioloop.IOLoop.current().start()

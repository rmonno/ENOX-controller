#!/usr/bin/env python
# -*- coding: utf-8 -*-
# #
# # roberto monno r.monno@nextworks.it
import sys
import os
import logging
import subprocess
import argparse as ap
import bottle
import threading
from watchdog.observers import Observer
from watchdog.events import *
import json

# logger
MLOG = logging.getLogger("media-server")
hdlr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s: [%(levelname)s] %(message)s')
hdlr.setFormatter(formatter)
MLOG.addHandler(hdlr)
MLOG.setLevel(logging.DEBUG)

CATALOG_APPEND = None
CATALOG_REMOVE = None
CATALOG_GET = None
PLAY_MP3 = None
PLAY_MP4 = None


@bottle.get('/media_catalog')
def media_catalog():
    MLOG.info("Enter http media_catalog")
    catalog = CATALOG_GET()

    if not len(catalog):
        bottle.abort(500, "Empty Catalog!")

    info = {'catalog':[]}
    for c_ in catalog:
        info['catalog'].append({'title': c_})

    return json.dumps(info, sort_keys=True, indent=4,
                      separators=(',', ': '))


@bottle.post('/media_play')
def media_play():
    if bottle.request.headers['content-type'] != 'application/json':
        bottle.abort(500, 'Application Type must be json!')

    title_ = bottle.request.json['title']
    MLOG.info("Enter http media_play: title=%s" % title_)

    if title_.endswith('mp3'):
        (ret, descr) = PLAY_MP3(title_)

    elif title_.endswith('mp4'):
        (ret, descr) = PLAY_MP4(title_)
    else:
        (ret, descr) = (False, "Encoding Type is not supported!")

    if ret != True:
        bottle.abort(500, "Play error: %s" % descr)

    return bottle.HTTPResponse(body=descr, status=201)


class MediaPlay:
    def __init__(self, address, port, catalog_dir):
        global PLAY_MP3
        global PLAY_MP4

        self.__address = address
        self.__port = port
        self.__dir = catalog_dir

        self.__check_cmd_exists('cvlc')
        PLAY_MP3 = self.play_mp3
        PLAY_MP4 = self.play_mp4
        MLOG.debug("Configured MediaPlay: addr=%s, port=%s, dir=%s",
                   address, port, catalog_dir)

    def __check_cmd_exists(self, cmd):
        subprocess.check_call([cmd, '--version'])

    def play_mp3(self, fname):
        f_ = self.__dir + '/' + fname
        if not os.path.exists(f_):
            return (False, "The path (%s) doesn't exist!" % f_)

        cmd_ = "cvlc -vvv --play-and-exit \"" + f_ + "\" " +\
               "--sout '#standard{access=%s,mux=%s,dst=%s:%s}'" %\
               ('http', 'ogg', self.__address, self.__port)
        MLOG.debug(cmd_)
        os.system(cmd_)

        return (True, "Operation completed")

    def play_mp4(self, fname):
        f_ = self.__dir + '/' + fname
        if not os.path.exists(f_):
            return (False, "The path (%s) doesn't exist!" % f_)

        cmd_ = "cvlc -vvv --play-and-exit \"" + f_ + "\" " +\
               "--sout '#transcode{vcodec=mp4v,acodec=mpga,vb=800,ab=128" +\
               ",deinterlace}:standard{access=%s,mux=%s,dst=%s:%s}'" %\
               ('http', 'ogg', self.__address, self.__port)
        MLOG.debug(cmd_)
        os.system(cmd_)

        return (True, "Operation completed")


class ChangeHandler (PatternMatchingEventHandler):
    def __init__ (self, extensions):
        ps_ = ['*.' + e for e in extensions]
        PatternMatchingEventHandler.__init__(self, patterns=ps_)

    def on_any_event (self, event):
        pass

    def on_created (self, event):
        MLOG.debug("on_created event: %s", str(event))
        (dir_, file_) = os.path.split(event.src_path)
        CATALOG_APPEND(file_)

    def on_deleted (self, event):
        MLOG.debug("on_deleted event: %s", str(event))
        (dir_, file_) = os.path.split(event.src_path)
        CATALOG_REMOVE(file_)

    def on_modified (self, event):
        pass

    def on_moved (self, event):
        pass


class MediaObserver:
    def __init__(self, directory, extensions):
        global CATALOG_APPEND
        global CATALOG_REMOVE
        global CATALOG_GET

        self.__mutex = threading.Lock()
        self.__obs = Observer(timeout=1)
        self.__obs.schedule(ChangeHandler(extensions),
                            path=directory, recursive=False)
        self.__dir = directory
        self.__catalog = [f for f in os.listdir(directory)
                          if f.endswith(tuple(extensions))]

        CATALOG_APPEND = self.catalog_append
        CATALOG_REMOVE = self.catalog_remove
        CATALOG_GET = self.catalog_get

        MLOG.debug("Configured observer: dir=%s, catalog=%s, extensions=%s",
                   directory, self.__catalog, extensions)

    def catalog_append(self, fname):
        try:
            self.__mutex.acquire()
            self.__catalog.append(fname)
            MLOG.debug("Catalog=%s", self.__catalog)

        finally:
            self.__mutex.release()

    def catalog_remove(self, fname):
        try:
            self.__mutex.acquire()
            self.__catalog.remove(fname)
            MLOG.debug("Catalog=%s", self.__catalog)

        finally:
            self.__mutex.release()

    def catalog_get(self):
        try:
            self.__mutex.acquire()
            return self.__catalog

        finally:
            self.__mutex.release()

    def run(self):
        self.__obs.start()

    def waiting_stop(self):
        MLOG.debug("waiting stop...")
        self.__obs.stop()
        self.__obs.join()

class MediaServer(object):
    def __init__(self, catalog, waddr, wport, saddr, sport, mtypes):
        self._media = MediaObserver(catalog, mtypes)
        self._play  = MediaPlay(saddr, sport, catalog)

        self._waddr = waddr
        self._wport = wport

    def run(self):
        try:
            self._media.run()
            bottle.run(host=self._waddr, port=self._wport, debug=True)

        except bottle.BottleException as e:
            MLOG.error("MediaServer end with error: %s" % e)

        except Exception as e:
            MLOG.warning("MediaServer stop: %s" % e)

        finally:
            self._media.waiting_stop()


def main(argv=None):
    psr_ = ap.ArgumentParser(description='Media Server Application',
                             epilog='Report bugs to <r.monno@nextworks.it>',
                             formatter_class=ap.ArgumentDefaultsHelpFormatter)

    psr_.add_argument('--catalog-dir', default='/tmp',
                      help='catalog directory')

    psr_.add_argument('--web_addr', default='127.0.0.1',
                      help='listen address for http requests')

    psr_.add_argument('--web_port', default='8081',
                      help='listen port for http requests')

    psr_.add_argument('--stream_addr', default='127.0.0.1',
                      help='streaming address for http connections')

    psr_.add_argument('--stream_port', default='9999',
                      help='streaming port for http connections')

    psr_.add_argument('media_types', nargs='+',
                      help='media types (file extensions)')

    rets_ = psr_.parse_args()
    MLOG.debug("Options=%s" % rets_)

    ms_ = MediaServer(rets_.catalog_dir,
                      rets_.web_addr, rets_.web_port,
                      rets_.stream_addr, rets_.stream_port,
                      rets_.media_types)
    ms_.run()

    MLOG.info("Bye Bye...")
    return True


if __name__ == "__main__":
    sys.exit(main())

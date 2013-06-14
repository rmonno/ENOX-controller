# Copyright 2008 (C) Nicira, Inc.
#
# This file is part of NOX.
#
# NOX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# NOX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with NOX.  If not, see <http://www.gnu.org/licenses/>.
# ----------------------------------------------------------------------
import sys
import os
import logging

import bottle
import threading
from watchdog.observers import Observer
from watchdog.events import *
import json

from nox.lib.core import Component

# update sys python path
KEY = 'nox-classic'
BASEPATH  = os.path.dirname(os.path.abspath(sys.argv[0]))
NOX_INDEX = BASEPATH.find(KEY)

LIBS_PATH = BASEPATH[0:NOX_INDEX-1]
sys.path.insert(0, LIBS_PATH)

IDL_FIND_PATH = BASEPATH[0:NOX_INDEX] + KEY + '/build/src'
for (root, dirs, names) in os.walk(IDL_FIND_PATH):
    if 'idl' in dirs:
        sys.path.insert(0, root + '/idl')


import libs as nxw_utils

MLOG = nxw_utils.ColorLog(logging.getLogger('media-server'))
CATALOG_APPEND = None
CATALOG_REMOVE = None
CATALOG_GET = None


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

    bottle.abort(500, "Not implemented yet!")


class ChangeHandler (PatternMatchingEventHandler):
    def __init__ (self):
        PatternMatchingEventHandler.__init__(self, patterns=['*.mp3'])

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
    def __init__ (self, directory):
        global CATALOG_APPEND
        global CATALOG_REMOVE
        global CATALOG_GET

        self.__mutex = threading.Lock()
        self.__obs = Observer(timeout=10)
        self.__obs.schedule(ChangeHandler(), path=directory, recursive=False)
        self.__dir = directory
        self.__catalog = [f for f in os.listdir(directory)
                          if f.endswith('.mp3')]

        CATALOG_APPEND = self.catalog_append
        CATALOG_REMOVE = self.catalog_remove
        CATALOG_GET = self.catalog_get

        self.__obs.start()
        MLOG.debug("Started MEDIA observer: dir=%s, catalog=%s",
                   directory, self.__catalog)

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

    def stop(self):
        MLOG.info("Stopping MEDIA observer...")
        self.__obs.stop()

    def join(self):
        MLOG.info("Joining MEDIA observer...")
        self.__obs.join()


class MediaServer(Component):
    CONFIG_FILE = LIBS_PATH + "/libs/" + "nox_topologymgr.cfg"

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self._conf_ms = nxw_utils.MediaServConfigParser(self.CONFIG_FILE)
        self._conf_ws = nxw_utils.WebServConfigParser(self.CONFIG_FILE)
        self._media = None

    def configure(self, configuration):
        try:
            self._media = MediaObserver(self._conf_ms.catalog_dir)

        except Exception as e:
            MLOG.error(str(e))
            assert (False)

    def install(self):
        self.post_callback(int(self._conf_ms.timeout), self.timer_handler)

    def getInterface(self):
        return str(MediaServer)

    def timer_handler(self):
        MLOG.debug("Starting media-service thread")
        try:
            bottle.run(host=self._conf_ws.host, port=self._conf_ms.port,
                       debug=self._conf_ws.debug)

        except Exception:
            self._media.stop()
            self._media.join()


def getFactory():
    class Factory:
        def instance(self, ctxt):
            return MediaServer(ctxt)

    return Factory()

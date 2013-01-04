#
# Copyright (C) 2012 Nextworks s.r.l.
#
# @LICENSE_BEGIN@
# @LICENSE_END@
#
# Written by: Francesco Salvestrini <f DOT salvestrini AT nextworks DOT it>
#

import threading

class StoppableThread(threading.Thread):
    def __init__(self,
                 group   = None,
                 target  = None,
                 name    = None,
                 args    = (),
                 kwargs  = None,
                 verbose = None):
        super(StoppableThread, self).__init__(group,
                                              target,
                                              name,
                                              args,
                                              kwargs,
                                              verbose)
        self.__halt = threading.Event()
        assert(self.__halt is not None)

    def __del__(self):
        self.stop()

    def stop(self):
        self.__halt.set()

    def start(self):
        self.__halt.clear()
        super(StoppableThread, self).start()

    def is_stopping(self):
        return self.__halt.is_set()

if __name__ == '__main__':
    pass

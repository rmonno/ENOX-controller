# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

""" Color Log module """

from termcolor import colored
from datetime import datetime


class ColorLog(object):
    """ ColorLog object """
    colormap = dict(
        debug=dict(color='grey', attrs=['bold']),
        info=dict(color='green', attrs=['bold']),
        warning=dict(color='yellow', attrs=['bold']),
        error=dict(color='red', attrs=['bold']),
        critical=dict(color='magenta', attrs=['bold']),
    )

    def __init__(self, logger):
        self._log = logger

    def __getattr__(self, name):
        if name in ['debug', 'info', 'warning', 'error', 'critical']:
            t = "[" + datetime.now().strftime("%D %H:%M:%S.%f") + "] "
            return lambda s, * args: getattr(self._log, name)(
                colored(t + str(s), **self.colormap[name]), *args)

        return getattr(self._log, name)

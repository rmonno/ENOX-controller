# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Roberto Monno

""" Color Log module """

from termcolor import colored


class ColorLog(object):
    """ ColorLog object """
    colormap = dict(
        debug=dict(color='grey', attrs=['bold']),
        info=dict(color='yellow', attrs=['bold']),
        warning=dict(color='yellow', attrs=['bold']),
        error=dict(color='red', attrs=['bold']),
        critical=dict(color='red', attrs=['bold']),
    )

    def __init__(self, logger):
        self._log = logger

    def __getattr__(self, name):
        if name in ['debug', 'info', 'warning', 'error', 'critical']:
            return lambda s, * args: getattr(self._log, name)(
                colored(s, **self.colormap[name]), *args)

        return getattr(self._log, name)

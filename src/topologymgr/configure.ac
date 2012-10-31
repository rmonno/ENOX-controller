#
# configure.ac
#
# (C) 2012 Nextworks SRL
#
# Written by: Francesco Salvestrini <f DOT salvestrini AT nextworks DOT it>
#

AC_INIT([FIBRE],
        [0.1],
        [a.canessa@nextworks.it],
        [fibre],
        [http://www.fibre-ict.eu//])

AC_PREREQ([2.68])

AM_INIT_AUTOMAKE([1.10 -Wall no-define])

AC_MSG_NOTICE([Testing configure...])

build_cli=yes

AS_IF([test $build_cli = yes],[
    AM_PATH_PYTHON([2.7],,[
        AC_MSG_ERROR([Missing required python interpreter (>= 2.7)])
    ])

    # Modules in the standard library (see http://docs.python.org/library) ...
#    AX_PYTHON_MODULE([sys])
#    AX_PYTHON_MODULE([os])
#    AX_PYTHON_MODULE([inspect])
#    AX_PYTHON_MODULE([threading])
#    AX_PYTHON_MODULE([Queue])
#    AX_PYTHON_MODULE([time])
#    AX_PYTHON_MODULE([getopt])
#    AX_PYTHON_MODULE([struct])
#    AX_PYTHON_MODULE([shlex])
#    AX_PYTHON_MODULE([re])
#    AX_PYTHON_MODULE([ConfigParser])
#    AX_PYTHON_MODULE([xml.dom])
#    AX_PYTHON_MODULE([xml.etree.ElementTree])
#    AX_PYTHON_MODULE([xmlrpclib])
#    AX_PYTHON_MODULE([telnetlib])

#    AC_PATH_PROG([PYFLAKES], [pyflakes], [ /bin/true ])
#    AC_PATH_PROG([PYLINT],   [pylint],   [ /bin/true ])
])

AC_CONFIG_FILES([
    Makefile
])

AC_OUTPUT

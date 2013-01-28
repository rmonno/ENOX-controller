#
# configure.ac
#
# (C) 2009 Nextworks SRL
#
# Written by: Francesco Salvestrini <f DOT salvestrini AT nextworks DOT it>
# 	      Fabio Nieri <f DOT nieri AT nextworks DOT it>
#

AC_INIT([gmpls-builder],[m4_esyscmd(build-aux/git-version-gen .tarball-version)],[f.salvestrini@nextworks.it],[gmpls-builder])

AC_PREREQ([2.61])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.10 foreign no-installman no-installinfo -Wall])

AC_PROG_SED
AC_PROG_GREP
AC_PATH_PROG([SORT], [sort])
AC_PATH_PROG([UNIQ], [uniq])
AC_PATH_PROG([GIT],  [git])

AC_PATH_PROG([DOT],  [dot])
AS_IF([test x"${DOT}" = x""],[
  AC_MSG_NOTICE([your system lacks graphviz support])
])

AC_PREFIX_DEFAULT(`pwd`/build)

checkoutroot="`pwd`/checkout"
AC_ARG_WITH([checkoutroot],[AS_HELP_STRING([--with-checkoutroot],[use specified checkout dir])],[checkoutroot="${withval}"],[])

AS_IF([test -z "$checkoutroot"],[
 AC_MSG_ERROR([You must choose a Checkoutroot path])
])
AC_SUBST(checkoutroot)

ignore_suggests=True
AC_ARG_ENABLE([scratch],
    AS_HELP_STRING([--enable-scratch], [Enable scratch build]))

AS_IF([test "x$enable_scratch" = "xyes"], [
ignore_suggests=False
])
AC_SUBST(ignore_suggests)

AC_CONFIG_FILES([
        Makefile
        build-aux/jhbuild_conf.py
])

AC_CONFIG_FILES([ builder ], [ chmod +x builder ])

AC_OUTPUT

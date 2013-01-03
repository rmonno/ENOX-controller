#
# Makefile.am
#
# (C) 2012 Nextworks SRL
#
# Written by: Francesco Salvestrini <f DOT salvestrini AT nextworks DOT it>
# test -f ./$@.in || srcdir=$(srcdir)/; \
#	  $(edit) $${srcdir}$@.in >$@.tmp
#


pymodulesdir = $(pythondir)

#MODULES =					\
#	testing/__init__.py

nobase_pymodules_PYTHON =			\
	$(MODULES)

CLEANFILES  =
EXTRA_DIST  =
bin_SCRIPTS =

topologymgrd: Makefile
	rm -f $@ $@.tmp
	cp $@.in $@.tmp
	chmod a-w $@.tmp
	chmod u+x $@.tmp
	mv $@.tmp $@

topologymgrd: $(srcdir)/topologymgrd.in
EXTRA_DIST += topologymgrd.in

bin_SCRIPTS += topologymgrd

CLEANFILES += $(bin_SCRIPTS)

pkgconfigdir   = $(libdir)/pkgconfig
pkgconfig_DATA = topologymgrd.pc

PYPATH = $(abs_top_builddir)/src/libs:$(abs_top_srcdir)/src/libs

PYL = $(PYLINT) --rcfile=$(abs_top_srcdir)/src/pylint.conf

check-local-static-pylint:
	for i in $(bin_SCRIPTS) ; do					\
		echo "Linting script $$i ..." ;				\
		PYTHONPATH=$(PYPATH):$$PYTHONPATH  $(PYL) -E $$i ||	\
			exit 1 ;					\
	done
	for i in $(MODULES) ; do					\
		echo "Linting module $$i ..." ;				\
		PYTHONPATH=$(PYPATH):$$PYTHONPATH  $(PYL) -E $$i ||	\
			exit 1 ;					\
	done

check-local-static-pyflakes:
	for i in $(bin_SCRIPTS) ; do		\
		$(PYFLAKES) $$i || exit 1 ;	\
	done
	$(PYFLAKES) $(srcdir)/topologymgr
	$(PYFLAKES) $(builddir)/topologymgr

check-local-static: check-local-static-pyflakes check-local-static-pylint

check-local-unit:
	for i in $(MODULES) ; do					     \
		echo "Testing module $$i ..." ;				     \
		MODULE="`echo $$i | $(SED) -e 's,\/,\.,' -e 's,\.py$$,,'`" ; \
		PYTHONPATH=$(PYPATH):$$PYTHONPATH			     \
		    $(PYTHON) -tt -m $$MODULE || {			     \
			echo "Module $$i failed to pass unit tests" ;	     \
			exit 1 ;					     \
		}							     \
	done

check-local: check-local-static check-local-unit

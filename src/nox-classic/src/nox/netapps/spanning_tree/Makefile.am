include ../../../Make.vars

EXTRA_DIST =	\
	__init__.py	\
	meta.json	\
	spanning_tree.py

NOX_RUNTIMEFILES =	\
	__init__.py \
	meta.json	\
	spanning_tree.py

all-local:
	@dlist="$(NOX_RUNTIMEFILES)";for f in $$dlist; do \
	  if test -f $(srcdir)/$$f && test ! -f $$f; then \
		ln -sf $(srcdir)/$$f $(builddir)/$$f;\
	  fi;\
	done;

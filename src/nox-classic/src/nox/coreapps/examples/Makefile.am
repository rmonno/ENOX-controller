include ../../../Make.vars

SUBDIRS = t

EXTRA_DIST =\
	meta.json		\
	__init__.py		\
	packetdump.py		\
	pyswitch.py		\
	pyloop.py		\
	monitor.py		\
	countdown.py		\
	dnsspy.py		\
	topologymgr.py

NOX_RUNTIMEFILES = meta.json	\
	__init__.py		\
	packetdump.py		\
	pyswitch.py		\
	pyloop.py		\
	monitor.py		\
	countdown.py		\
	dnsspy.py		\
	connections.py		\
	pce_conn.py		\
	fpce_dm.py		\
	topologymgr.py

all-local: nox-all-local
install-exec-hook: nox-install-local

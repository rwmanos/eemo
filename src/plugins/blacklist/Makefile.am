# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

AM_CFLAGS =			-I$(srcdir)/.. \
				-I$(srcdir)/../..

lib_LTLIBRARIES = 		libeemo_blacklist.la

libeemo_blacklist_la_SOURCES =	eemo_blacklist_entry.c \
				eemo_blacklist_stats.c \
				eemo_blacklist_stats.h \
				../eemo_plugin_log.c \
				../eemo_plugin_log.h

libeemo_blacklist_la_LDFLAGS =	-version-info @EEMO_BLACKLIST_VERSION_INFO@

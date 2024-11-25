#
# SI6 Networks' ipv6mon Makefile (for GNU make)
#
# Notes to package developers:
#
# By default, binaries will be installed in /usr/local/bin, manual pages in
# /usr/local/man, and configuration file in /etc
#
# The path of the binaries  can be overriden by setting "PREFIX" variable 
# accordingly. The path of the manual pages can be overriden by setting
# the MANPREFIX variable. Typically, packages will set these variables as 
# follows:
#
# PREFIX=/usr/
# MANPREFIX=/usr/share
#
# Finally, please note that this makefile supports the DESTDIR variable, as 
# typically employed by package developers.


CC= gcc
CFLAGS+= -Wall -Wno-address-of-packed-member -Wno-missing-braces
LDFLAGS+= -lpcap -lm

ifeq ($(shell uname),SunOS)
  LDFLAGS+=-lsocket -lnsl
  OS=SunOS
endif


ifndef PREFIX
    PREFIX=/usr/local
    ifndef MANPREFIX
	MANPREFIX=/usr/local
    endif
else
    ifndef MANPREFIX
	MANPREFIX=/usr/share
    endif
endif

ETCPATH= $(DESTDIR)/etc
MANPATH= $(DESTDIR)$(MANPREFIX)/man
BINPATH= $(DESTDIR)$(PREFIX)/bin
SBINPATH= $(DESTDIR)$(PREFIX)/sbin
SRCPATH= .

SBINTOOLS= ipv6mon
BINTOOLS= 
TOOLS= $(BINTOOLS) $(SBINTOOLS)
LIBS= 

all: $(TOOLS)

ipv6mon: $(SRCPATH)/ipv6mon.c $(SRCPATH)/ipv6mon.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o ipv6mon $(SRCPATH)/ipv6mon.c $(LIBS) $(LDFLAGS)

clean: 
	rm -f $(TOOLS) $(LIBS)

install: all
	echo "Please use the platform-specific scripts."

uninstall:
	echo "Please use the platform-specific scripts."

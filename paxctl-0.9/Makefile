CC:=gcc
CFLAGS:=-Os -ggdb -Wall -W -Wcast-qual -Wcast-align -Wbad-function-cast -Wshadow -Wwrite-strings -Wnested-externs -Winline -Wredundant-decls -Waggregate-return -Wformat=2 -Wpointer-arith -Wconversion -Wmissing-declarations -Wmissing-prototypes
# -Wunreachable-code -Wdisabled-optimization
DESTDIR:=
LDFLAGS:=
MANDIR:=/usr/share/man/man1
#MKDIR:=mkdir -p
INSTALL:=install
PROG:=paxctl
RM:=rm

all: $(PROG)

$(PROG): $(PROG).o
	$(CC) $(LDFLAGS) -o $@ $<

$(PROG).o: $(PROG).c $(PROG).h $(PROG)-elf.c
	$(CC) -c $(CFLAGS) -o $@ $<

install: $(PROG)
#	$(MKDIR) $(DESTDIR)/sbin $(DESTDIR)$(MANDIR)
	$(INSTALL) -D --owner 0 --group 0 --mode a=rx $(PROG) $(DESTDIR)/sbin/$(PROG)
	$(INSTALL) -D --owner 0 --group 0 --mode a=r $(PROG).1 $(DESTDIR)/$(MANDIR)/$(PROG).1

clean:
	$(RM) -f $(PROG) $(PROG).o core

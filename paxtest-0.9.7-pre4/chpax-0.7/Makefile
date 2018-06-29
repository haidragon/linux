##
## Makefile for chpax.c
##
## The PaX project : http://pax.grsecurity.net/
##

SRC	= chpax.c io.c elf32.c elf64.c aout.c flags.c
OBJ	= $(SRC:.c=.o)
RM	= rm -f 
TARGET	= chpax
CC	= gcc
CFLAGS	= -Wall -W -g3
STRIP	= strip
#STRIP	= touch
CP	= cp
DESTDIR =
MANDIR	= /usr/share/man/man1/
MKDIR	= mkdir -p

all	: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET)

install	: all
	$(STRIP) $(TARGET)
	$(MKDIR) $(DESTDIR)/sbin/ $(DESTDIR)$(MANDIR)
	$(CP) $(TARGET) $(DESTDIR)/sbin/
	$(CP) $(TARGET).1 $(DESTDIR)$(MANDIR)

clean	:
	$(RM) *.o *~ \#* *\#

fclean	: clean
	$(RM) $(TARGET)

CC =	gcc
CFLAGS  =       -ggdb -DDEBUG
CFLAGS_EXEC =	-I../include -ggdb -Os -fomit-frame-pointer -mpreferred-stack-boundary=2
LFLAGS = 	-ldl -lpthread

all: quenya

quenya: hijack.o unpack.o sym.o rebuild.o elf2shell.o disas.o args.o main.o inject.o elf_mmap.o sht.o reloc.o list.o banner.o help.o misc.o pht.o rel.o
	$(CC) $(CFLAGS) -o quenya hijack.o unpack.o sym.o rebuild.o disas.o elf2shell.o args.o main.o inject.o elf_mmap.o sht.o reloc.o list.o banner.o help.o misc.o pht.o rel.o libdasm-1.5/libdasm.a $(LFLAGS)

clean:
	rm -f *.o quenya us_exec/*.o us_exec/exec.a


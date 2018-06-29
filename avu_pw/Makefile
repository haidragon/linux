all: avu
avu: avu.o util.o entry.o chkbin.o usage.o parse.o memv.o log.o signal.o plt.o ptrace.o rebuild.o args.o unpack.o elf.o
	gcc -g -fno-stack-protector avu.o util.o entry.o chkbin.o usage.o parse.o memv.o log.o signal.o plt.o ptrace.o rebuild.o args.o unpack.o elf.o -o avu

avu.o: avu.c
	gcc -g -c avu.c
util.o: util.c
	gcc -g -c util.c
entry.o: entry.c
	gcc -g -c entry.c
chkbin.o: chkbin.c
	gcc -g -c chkbin.c
usage.o: usage.c
	gcc -g -c usage.c
parse.o: parse.c
	gcc -g -c parse.c
log.o: log.c
	gcc -g -c log.c
signal.o: signal.c
	gcc -g -c signal.c
plt.o: plt.c	
	gcc -g -c plt.c
ptrace.o: ptrace.c
	gcc -g -c ptrace.c
rebuild.o: rebuild.c
	gcc -g -c rebuild.c
args.o:	args.c
	gcc -g -c args.c
unpack.o: unpack.c
	gcc -g -c unpack.c
elf.o: elf.c
	gcc -g -c elf.c

clean:
	rm -f *.o avu

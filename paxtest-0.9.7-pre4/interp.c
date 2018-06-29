#ifdef __UCLIBC__
const char __invoke_dynamic_linker__[] __attribute__ ((section (".interp"))) = "/lib/ld-uClibc.so.0";
#else
const char __invoke_dynamic_linker__[] __attribute__ ((section (".interp"))) = "/lib/ld-linux.so.2";
#endif

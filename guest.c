#include <stddef.h>
#include <stdint.h>

static inline uint32_t inb(uint16_t port) {
	uint32_t ret;
	asm("in %1, %0" : "=a"(ret) : "Nd"(port) : "memory" );
	return ret;
}

static inline void outb(uint16_t port, uint32_t value) {
	asm("out %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {
	const char *p = "Hello, world!\n";

	for (p = "Hello, world!\n"; *p; ++p)
		outb(0xE9, *p);

	*(long *) 0x400 = 42;

	for (;;)
		asm("hlt" : /* empty */ : "a" (42) : "memory");
}

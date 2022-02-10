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

static void print(const void *str) {
    static const uint16_t PORT = 0xEA;

    /*
     * Because the entire memory space is 2MB,
     * we can refer only to the lowest 32bit
     */
    intptr_t ptr = (intptr_t)str;
    uint32_t low = (uint32_t)(ptr & 0xFFFFFFFF);
    outb(PORT, low);
}

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {
    const char *p = "Hello, world!";

    print(p);

    *(long *) 0x400 = 42;

    for (;;)
        asm("hlt" : /* empty */ : "a" (42) : "memory");
}

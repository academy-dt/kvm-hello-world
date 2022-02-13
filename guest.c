#include <stddef.h>
#include <stdint.h>

#include "shared.h"

static inline uint32_t inb(uint16_t port) {
    uint32_t ret;
    asm("in %1, %0" : "=a"(ret) : "Nd"(port) : "memory" );
    return ret;
}

static inline void outb(uint16_t port, uint32_t value) {
    asm("out %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

static int u32toa(uint32_t x, char *buffer, size_t len) {
    if (!buffer || len == 0) {
        return -1;
    }

    if (x == 0) {
        buffer[0] = '0';
        buffer[1] = '\0';
        return 0;
    }

    /*
     * Find largest base 10 dividor.
     * Start with max possible value for a 32bit number.
     */
    size_t div;
    for (div = 1000000000; x / div == 0; div /= 10);

    size_t i;
    for (i = 0; div > 0 && i < len - 1; ++i) {
        buffer[i] = (x / div) + '0';
        x        %= div;
        div      /= 10;
    }
    buffer[i] = '\0';

    return (i < len - 1) ? 0 : -1;
}

static void print(const void *str) {
    /*
     * Because the entire memory space is 2MB,
     * we can refer only to the lowest 32bit
     */
    intptr_t ptr = (intptr_t)str;
    uint32_t low = (uint32_t)(ptr & 0xFFFFFFFF);
    outb(PORT_PRINT, low);
}

static void print_u32(uint32_t num) {
    char buffer[32]; // Enough to represent any 32bit number
    if (u32toa(num, buffer, sizeof(buffer)) == 0) {
        print(buffer);
    } else {
        print("Print u32: conversion failed");
    }
}

static void generate_exits(unsigned count) {
    for (unsigned i = 0; i < count; ++i) {
        print("Test #vmexit");
    }
}

static uint32_t exits(void) {
    return inb(PORT_EXITS);
}

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {

    generate_exits(7);
    uint32_t vm_exits = exits();

    print_u32(vm_exits);

    *(long *) 0x400 = 42;

    for (;;)
        asm("hlt" : /* empty */ : "a" (42) : "memory");
}

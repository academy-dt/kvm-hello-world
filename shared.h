#ifndef SHARED_H
#define SHARED_H

#define PORT_PRINT  0xE8
#define PORT_RETVAL 0xE9
#define PORT_EXITS  0xEA
#define PORT_OPEN   0xEB
#define PORT_READ   0xEC
#define PORT_WRITE  0xED
#define PORT_CLOSE  0xEF

#define LEN_BITS 11
#define LEN_MAX  (1 << LEN_BITS)
#define LEN_MASK (LEN_MAX - 1)

#define BUF_BITS 21
#define BUF_MAX  (1 << BUF_BITS)
#define BUF_MASK (BUF_MAX - 1)

#endif /* SHARED_H */

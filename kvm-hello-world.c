#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <linux/kvm.h>

#include "shared.h"

/* CR0 bits */
#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)

/* CR4 bits */
#define CR4_VME 1
#define CR4_PVI (1U << 1)
#define CR4_TSD (1U << 2)
#define CR4_DE (1U << 3)
#define CR4_PSE (1U << 4)
#define CR4_PAE (1U << 5)
#define CR4_MCE (1U << 6)
#define CR4_PGE (1U << 7)
#define CR4_PCE (1U << 8)
#define CR4_OSFXSR (1U << 8)
#define CR4_OSXMMEXCPT (1U << 10)
#define CR4_UMIP (1U << 11)
#define CR4_VMXE (1U << 13)
#define CR4_SMXE (1U << 14)
#define CR4_FSGSBASE (1U << 16)
#define CR4_PCIDE (1U << 17)
#define CR4_OSXSAVE (1U << 18)
#define CR4_SMEP (1U << 20)
#define CR4_SMAP (1U << 21)

#define EFER_SCE 1
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)
#define EFER_NXE (1U << 11)

/* 32-bit page directory entry bits */
#define PDE32_PRESENT 1
#define PDE32_RW (1U << 1)
#define PDE32_USER (1U << 2)
#define PDE32_PS (1U << 7)

/* 64-bit page * entry bits */
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_ACCESSED (1U << 5)
#define PDE64_DIRTY (1U << 6)
#define PDE64_PS (1U << 7)
#define PDE64_G (1U << 8)

#define THREAD_ERR ((void *)1)

#define LOG(fmt, ...) \
    do { \
        fprintf(stdout, fmt "\n", ##__VA_ARGS__); \
        fflush(stdout); \
    } while(0)

/*
 * We assume that only a single "host"-file can be opened by the guest.
 * This is the FD for that file.
 */
static int file_fd = -1;
static int retval = 0;

struct vm {
    int sys_fd;
    int fd;
    char *mem;
};

void vm_init(struct vm *vm, size_t mem_size)
{
    int api_ver;
    struct kvm_userspace_memory_region memreg;

    vm->sys_fd = open("/dev/kvm", O_RDWR);
    if (vm->sys_fd < 0) {
        perror("open /dev/kvm");
        exit(1);
    }

    api_ver = ioctl(vm->sys_fd, KVM_GET_API_VERSION, 0);
    if (api_ver < 0) {
        perror("KVM_GET_API_VERSION");
        exit(1);
    }

    if (api_ver != KVM_API_VERSION) {
        fprintf(stderr, "Got KVM api version %d, expected %d\n",
            api_ver, KVM_API_VERSION);
        exit(1);
    }

    vm->fd = ioctl(vm->sys_fd, KVM_CREATE_VM, 0);
    if (vm->fd < 0) {
        perror("KVM_CREATE_VM");
        exit(1);
    }

    if (ioctl(vm->fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0) {
        perror("KVM_SET_TSS_ADDR");
        exit(1);
    }

    vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (vm->mem == MAP_FAILED) {
        perror("mmap mem");
        exit(1);
    }

    madvise(vm->mem, mem_size, MADV_MERGEABLE);

    memreg.slot = 0;
    memreg.flags = 0;
    memreg.guest_phys_addr = 0;
    memreg.memory_size = mem_size;
    memreg.userspace_addr = (unsigned long)vm->mem;
    if (ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0) {
        perror("KVM_SET_USER_MEMORY_REGION");
        exit(1);
    }
}

struct vcpu {
    int fd;
    struct kvm_run *kvm_run;
};

void vcpu_init(struct vm *vm, struct vcpu *vcpu)
{
    vcpu->fd = ioctl(vm->fd, KVM_CREATE_VCPU, 0);
    if (vcpu->fd < 0) {
        perror("KVM_CREATE_VCPU");
        exit(1);
    }

    int vcpu_mmap_size = ioctl(vm->sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (vcpu_mmap_size <= 0) {
        perror("KVM_GET_VCPU_MMAP_SIZE");
        exit(1);
    }

    vcpu->kvm_run = mmap(NULL, vcpu_mmap_size, PROT_READ | PROT_WRITE,
                 MAP_SHARED, vcpu->fd, 0);
    if (vcpu->kvm_run == MAP_FAILED) {
        perror("mmap kvm_run");
        exit(1);
    }
}

uint32_t get_u32(struct vcpu *vcpu)
{
    char *raw_ptr = (char *)vcpu->kvm_run + vcpu->kvm_run->io.data_offset;
    uint32_t *value_ptr = (uint32_t *)raw_ptr;
    return *value_ptr;
}

char *get_string(char *vm_base, struct vcpu *vcpu)
{
    uint32_t offset = get_u32(vcpu);
    return vm_base + offset;
}

void get_buf_len(char *vm_base, struct vcpu *vcpu, void **buf, int *len)
{
    uint32_t value = get_u32(vcpu);
    *len = value & LEN_MASK;

    uint32_t offset = value >> LEN_BITS;
    *buf = vm_base + offset;
}

void put_u32(struct vcpu *vcpu, uint32_t value)
{
    char *raw_ptr = (char *)vcpu->kvm_run + vcpu->kvm_run->io.data_offset;
    uint32_t *value_ptr = (uint32_t *)raw_ptr;
    *value_ptr = value;
}

void handle_print(char *vm_base, struct vcpu *vcpu)
{
    char *str = get_string(vm_base, vcpu);
    LOG("Guest: %s", str);
}

int handle_open(char *vm_base, struct vcpu *vcpu)
{
    char *path = get_string(vm_base, vcpu);
    LOG("Handling open(%s)", path);

    if (file_fd != -1) {
        LOG("Failed! Already open");
        return -EALREADY;
    }

    /*
     * Note: We chose O_CREATE and O_APPEND just because that was convenient for testing.
     * Any set of flags should work here.
     */
    file_fd = open(path, O_RDWR | O_CREAT | O_APPEND, 0666);
    if (file_fd == -1) {
        LOG("Failed! Errno = %d", -errno);
        return -errno;
    }

    return 0;
}

int handle_read(char *vm_base, struct vcpu *vcpu)
{
    void *buf;
    int len;
    get_buf_len(vm_base, vcpu, &buf, &len);
    LOG("Handling read(%p, %d)", buf, len);

    if (file_fd == -1) {
        LOG("Failed! No file open");
        return -EINVAL;
    }

    int bytes = read(file_fd, buf, len);
    if (bytes == -1) {
        LOG("Failed! Errno = %d", -errno);
        return -errno;
    }

    return bytes;
}

int handle_write(char *vm_base, struct vcpu *vcpu)
{
    void *buf;
    int len;
    get_buf_len(vm_base, vcpu, &buf, &len);
    LOG("Handling write(%p, %d)", buf, len);

    if (file_fd == -1) {
        LOG("Failed! No file open");
        return -EINVAL;
    }

    int bytes = write(file_fd, buf, len);
    if (bytes == -1) {
        LOG("Failed! Errno = %d", -errno);
        return -errno;
    }

    return bytes;
}

void handle_close()
{
    LOG("Handling close()");

    if (file_fd == -1) {
        LOG("Aborted! No file open");
        return;
    }

    if (close(file_fd) == -1) {
        LOG("Failed! Errno = %d", -errno);
        return;
    }

    file_fd = -1;
}

int run_vm(char *vm_base, struct vcpu *vcpu, size_t sz)
{
    struct kvm_regs regs;
    uint64_t memval = 0;
    uint64_t vm_exits = 0;

    for (;;) {
        if (ioctl(vcpu->fd, KVM_RUN, 0) < 0) {
            perror("KVM_RUN");
            exit(1);
        }

        ++vm_exits;

        switch (vcpu->kvm_run->exit_reason) {
        case KVM_EXIT_HLT:
            goto check;

        case KVM_EXIT_IO:
            if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT) {
                switch (vcpu->kvm_run->io.port) {
                    case PORT_PRINT:
                        handle_print(vm_base, vcpu);
                        break;

                    case PORT_OPEN:
                        retval = handle_open(vm_base, vcpu);
                        break;

                    case PORT_READ:
                        retval = handle_read(vm_base, vcpu);
                        break;

                    case PORT_WRITE:
                        retval = handle_write(vm_base, vcpu);
                        break;

                    case PORT_CLOSE:
                        handle_close();
                        break;

                    default:
                        fprintf(stderr, "Got EXIT_IO_OUT from unknown port %d",
                                vcpu->kvm_run->io.port);
                        exit(1);
                }
                continue;
            } else if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_IN) {
                switch (vcpu->kvm_run->io.port) {
                    case PORT_RETVAL:
                        put_u32(vcpu, retval);
                        break;

                    case PORT_EXITS:
                        put_u32(vcpu, vm_exits);
                        break;

                    default:
                        fprintf(stderr, "Got EXIT_IO_IN from unknown port %d",
                                vcpu->kvm_run->io.port);
                        exit(1);
                }
                continue;
            }

            /* fall through */
        default:
            fprintf(stderr, "Got exit_reason %d,"
                " expected KVM_EXIT_HLT (%d)\n",
                vcpu->kvm_run->exit_reason, KVM_EXIT_HLT);
            exit(1);
        }
    }

 check:
    if (ioctl(vcpu->fd, KVM_GET_REGS, &regs) < 0) {
        perror("KVM_GET_REGS");
        exit(1);
    }

    if (regs.rax != 42) {
        printf("Wrong result: {E,R,}AX is %lld\n", regs.rax);
        return 1;
    }

    memcpy(&memval, &vm_base[0x400], sz);
    if (memval != 42) {
        printf("Wrong result: memory at 0x400 is %lld\n",
               (unsigned long long)memval);
        return 1;
    }

    return 0;
}

extern const unsigned char guest64[], guest64_end[];

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
    struct kvm_segment seg = {
        .base = 0,
        .limit = 0xffffffff,
        .selector = 1 << 3,
        .present = 1,
        .type = 11, /* Code: execute, read, accessed */
        .dpl = 0,
        .db = 0,
        .s = 1, /* Code/data */
        .l = 1,
        .g = 1, /* 4KB granularity */
    };

    sregs->cs = seg;

    seg.type = 3; /* Data: read/write, accessed */
    seg.selector = 2 << 3;
    sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

static void setup_long_mode(char *vm_base, struct kvm_sregs *sregs)
{
    uint64_t pml4_addr = 0x2000;
    uint64_t *pml4 = (void *)(vm_base + pml4_addr);

    uint64_t pdpt_addr = 0x3000;
    uint64_t *pdpt = (void *)(vm_base + pdpt_addr);

    uint64_t pd_addr = 0x4000;
    uint64_t *pd = (void *)(vm_base + pd_addr);

    pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
    pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
    pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;

    sregs->cr3 = pml4_addr;
    sregs->cr4 = CR4_PAE;
    sregs->cr0
        = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
    sregs->efer = EFER_LME | EFER_LMA;

    setup_64bit_code_segment(sregs);
}

int run_long_mode(char *vm_base, struct vcpu *vcpu)
{
    struct kvm_sregs sregs;
    struct kvm_regs regs;

    printf("Testing 64-bit mode\n");

    if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
        perror("KVM_GET_SREGS");
        exit(1);
    }

    setup_long_mode(vm_base, &sregs);

    if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
        perror("KVM_SET_SREGS");
        exit(1);
    }

    memset(&regs, 0, sizeof(regs));
    /* Clear all FLAGS bits, except bit 1 which is always set. */
    regs.rflags = 2;
    regs.rip = 0;
    /* Create stack at top of 2 MB page and grow down. */
    regs.rsp = 2 << 20;

    if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
        perror("KVM_SET_REGS");
        exit(1);
    }

    memcpy(vm_base, guest64, guest64_end-guest64);
    return run_vm(vm_base, vcpu, 8);
}

struct vexec {
    pthread_t thread_id;
    struct vcpu vcpu;
    char *vm_base;
};

void* run_thread(void *args) {
    if (!args) {
        return THREAD_ERR;
    }

    struct vexec *v = (struct vexec *)args;
    if (run_long_mode(v->vm_base, &v->vcpu)) {
        return THREAD_ERR;
    }

    return 0;
}

int main()
{
    static const size_t CPUS = 1;
    static const size_t VM_SIZE = 0x200000;

    int err;

    struct vm vm;
    struct vexec vexec[CPUS];

    LOG("PID = %d", getpid());

    vm_init(&vm, CPUS * VM_SIZE);

    for (size_t i = 0; i < CPUS; ++i) {
        struct vexec *v = &vexec[i];
        vcpu_init(&vm, &v->vcpu);
        v->vm_base = &vm.mem[i * VM_SIZE];
    }

    for (size_t i = 0; i < CPUS; ++i) {
        struct vexec *v = &vexec[i];
        err = pthread_create(&v->thread_id, NULL, run_thread, v);
        if (err) {
            LOG("Create thread failed, err = %d", err);
            return 1;
        }
    }

    for (size_t i = 0; i < CPUS; ++i) {
        void *retval;
        struct vexec *v = &vexec[i];
        err = pthread_join(v->thread_id, &retval);
        if (err) {
            LOG("Join thread failed, err = %d", err);
            return 1;
        }

        if (retval != 0) {
            LOG("Run failed");
            return 1;
        }
    }

    return 0;
}

# Homework 3 - Group programming

- Daniel Trugman 303922611
- Chen Gleichger 201050135

### (1) KVM: hypervisor, guest(s), and hypercalls

### Question a.1

What is the size of the guest (physical) memory? How and where in the
code does the hypervisor allocate it? At what host (virtual) address is this
memory mapped?

### Answer a.1

As we can see in the `main` function, we call `vm_init` with `mem_size = 0x200000`. That means we allocate 2MB of memory space.
The actual allocation happens at `vm->mem = mmap(NULL, mem_size, ...)` where we ask the OS to give up a memory mapping of that size.
The `mmap` call returns the virtual address of this memory space from the host's perspective.

### Question a.2

Besides the guest memory, what additional memory is allocated? What is
stored in that memory? Where in the code is this memory allocated? At what
host/guest? (virtual/physical?) address is it located?

### Answer a.2

The `vcpu_init` method allocates an additional control block for the vCPU.
It first asks the KVM how big that structure is by calling `vcpu_mmap_size = ioctl(vm->sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0)`,
and then allocates the memory at `vcpu->kvm_run = mmap(NULL, vcpu_mmap_size, ...)`.
Once again, the memory is allocated on the host, and the virtual address is stored in `vcpu->kvm_run`.
Later on, from inside `run_vm` we access this structure for information about the guest, such as the vmexit reason, IO info, etc.

The hypervisor then formats the guest memory and registers, to prepare for its
execution. (From here on, assume _"long"_ mode).

### Question a.3

The guest memory area is setup to contain the guest code, the guest page
table, and a stack. For each of these, identify where in the code it is setup,
and the address range it occupies (both guest-physical and host-virtual).

### Answer a.3

Inside `setup_long_mode` we can see the setup of the page tables.
We setup:
- PML4 at offset 0x2000
- PDPT at offset 0x3000
- PD at offset 0x4000
All relative to the beginning of the address space.
Meaning PML4 is at guest-physical address 0x2000 and host virtual address of `vm->mem + 0x2000`.

The stack is "allocated" at line 428: `regs.rsp = 2 << 20`.
Basically, `2 << 20` is the same value as `0x200000`, so we set the stack to be at the top of the address space.
In the guest-physical address, it will start at `0x200000` and grow down towards `0x0`.
In the host-virtual, it will start at `vm->mem + 0x200000` and grow down towards `vm->mem`.

The guest code segment is set up inside `setup_64bit_code_segment`.
We can see that the base of the segment is at address `0x0` (i.e `vm->mem` in host-virtual).
The actual copy of the copy into the guest's VM is at line 435: `memcpy(vm->mem, guest64, ...)`.
The guest code is exported as a extern byte array from the compile `guest.c` code.

```
0x000000 ---------------------------    --+
         Guest code                       |
0x001000 ---------------------------      |
         Nothing                          |
0x002000 ---------------------------      |
         PML4                             |
0x003000 ---------------------------      |
         PDPT                             |
0x004000 ---------------------------      +--- Single, 2MB page
         PD                               |
0x005000 ---------------------------      |
    .                                     |
    .      ^                              |
    .      |                              |
    .      |                              |
    .    STACK                            |
0x200000 ---------------------------    --+
```

### Question a.4

Examine the guest page table. How many levels does it have? How many
pages does it occupy? Describe the guest virtual-to-physical mappings: what
part(s) of the guest virtual address space is mapped, and to where?

### Answer a.4

The page table has 3 levels, each level occupies a single 4K memory region.
There is a single page mapped into the virtual address space, and that's a single 2M (PDE64_PS) page
that maps the entire memory space we allocated for this VM.

```
CR3 = 0x2000
         |
   +-----+
   |
   v
             PML4:
0x2000 ----> Entry | Where  | Bits
             ------+--------+----------------------------
             0     | 0x3000 | PRESENT, RW, USER
                        |
   +--------------------+
   |
   v
             PDPT:
0x3000 ----> Entry | Where  | Bits
             ------+--------+----------------------------
             0     | 0x4000 | PRESENT, RW, USER
                        |
   +--------------------+
   |
   v
             PDPT:
0x4000 ----> Entry | Where  | Bits
             ------+--------+----------------------------
             0     | 0x0    | PRESENT, RW, USER, PDE64_PS

```

For both (a.3) and (a.4), illustrate/visualize the hypervisor memory layout
and the guest page table structure and address translation. (Preferably in
text form).

### Question a.5

At what (guest virtual) address does the guest start execution? Where is
this address configured?

### Answer a.5

The guest starts execution at address 0, exactly where we placed our code.
We set the instruction pointer at line 426: `regs.rip = 0`.

Next, the hypervisor proceeds to run the guest. For simplicity, the guest code
(in _guest.c_) is very basic: one executable, a simple page table and a stack
(no switching). It prints "Hello, world!" using the `outb` instruction (writes
a byte to an IO port) which is a protected instruction that causes the guest to
exit to the hypervisor, which in turn prints the character.

(Notice how the `outb` instruction is embedded as assembly inside the guest's
C code; See [here](https://wiki.osdev.org/Inline_Assembly) for details on how
inline assembly works).

After the guest exits, the hypervisor regains control and checks the reason for
the exit to handle it accordingly.

### Question a.6

What port number does the guest use? How can the hypervisor know the port
number, and read the value written? Which memory buffer is used for this value?
How many exits occur during this print?

### Answer a.6

The guest uses port number `0xE9`.
This value is hardcoded into both applications, and when there's a vmexit, and the reason is `KVM_EXIT_IO` the host checks the conditions:
`if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT && vcpu->kvm_run->io.port == 0xE9) {`
And if they match the expected output, we print `vcpu->kvm_run->io.size` bytes stored at `vcpu->kvm_run->io.data_offset`.
Both of which are set by the `outb` command.

Finally, the guest writes the number 42 to memory and EAX register, and then
executes the `hlt` instruction.

### Question a.7

At what guest virtual (and physical?) address is the number 42 written?
And how (and where) does the hypervisor read it?

### Answer a.7

The number is written both to address `0x400` and to `rax`.
Once using: `*(long *)0x400 = 42` and once as an argument to the `hlt` inline assemblyl command.
When the hypervisor sess the `KVM_EXIT_HLT` reason, it first checks the `rax` value,
and then reads from the `0x400` address using: `memcpy(&memval, &vm->mem[0x400], sz);`

**(b) Extend with new hypercalls**

Implemented. See code at commit [e10baf28b1c1817d426acf61b00d4da75b38ae54](https://github.com/academy-dt/kvm-hello-world/commit/e10baf28b1c1817d426acf61b00d4da75b38ae54)

**(c) Filesystem para-virtualization**

Implemented. See code at commit [e10baf28b1c1817d426acf61b00d4da75b38ae54](https://github.com/academy-dt/kvm-hello-world/commit/e10baf28b1c1817d426acf61b00d4da75b38ae54)

**(d) Bonus: hypercall in KVM**

Not implemented

**(e) Multiple vCPUs**

Implemented e.1 using actual code, including:
- Virtual memory changes.
- Creating additional VCPUs.
- Fixed virtual memory base address propagation to all functions.
- Fixed RIP/RSP and segment definitions.
- Running everything from dedicated threads.
- Per-CPU members for all hypercalls.
- Easy configuration for more than 2 CPUs

But still, something doesn't work, and we don't know what.
Guest exists with SHUTDOWN the moment we call VMENTER for the second VCPU.

### (2) Containers and namespaces

In this assignment you will implement a simples container runtime that can
spawn a command in an isolated environment.

For this assignment, you need to understand the basics of Linux namespaces;
Read through __"Digging into Linux namespaces"__:
[part 1](https://blog.quarkslab.com/digging-into-linux-namespaces-part-1.html)
and
[part 2](https://blog.quarkslab.com/digging-into-linux-namespaces-part-2.html).

We will use the following steps to build a fully isolated environment for a
given process:

1. Create user namespace; remap the UIDs/GIDs in the new _userns_
2. Create uts namespaces; change hostname in the new _utsns_
3. Create ipc namespace
4. Create net namespace; create and configure veth interface pair
5. Create pid namespace
6. Create mnt namespace; mount /proc inside the new _mntns_

(Note that the process would run in an isolated environment, but would share
the same root filesystem as the parent, just in a separate _mntns_).

These steps can be done in userspace as follows:

            Parent shell                     Child shell
            -------------------------------  -----------------------------
          1                                  # (1) create (privileged) userns
          2
          3                                  $ unshare -U --kill-child /bin/bash
          4                                  $ echo "my-user-ns" > /proc/$$/comm
          5                                  $ id
          6                                  uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
          7
          8
          9   $ ps -e -o pid,comm | grep my-user-ns
         10   22310,my-user-ns?
         11
         12   $ sudo bash -c 'echo "0 1000 1000" > /proc/22310/uid_map'
         13   $ sudo bash -c 'echo "0 1000 1000" > /proc/22310/gid_map'
         14
         15                                  $ id
         16                                  uid=0(root) gid=0(root) groups=0(root),65534(nogroup)
         17
         18                                  # (2,3) create utsns and ipcns
         19
         20                                  $ unshare --ipc --uts --kill-child /bin/bash
         21                                  $ hostname isolated
         22                                  $ hostname
         23                                  isolated
         24
         25                                  # (4) create netns
         26                                  $ unshare --net --kill-child /bin/bash
         27                                  $ echo "my-net-ns" > /proc/$$/comm
         28
         29   $ ps -e -o pid,comm | grep my-user-ns
         30   22331,my-net-ns?
         31
         32   $ sudo ip link add veth0 type veth peer name peer0
         33   $ sudo ip link set veth0 up
         34   $ sudo ip addr add 10.11.12.13/24 dev veth0
         35
         36   $ sudo ip link set peer0 netns /proc/22331/ns/net
         37
         38                                  $ ip link
         39                                  1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000
         40                                      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
         41                                  9: peer0@if10: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
         42                                      link/ether 76:8d:bb:61:1b:f5 brd ff:ff:ff:ff:ff:ff link-netnsid 0
         43                                  $ ip link set lo up
         44                                  $ ip link set peer0 up
         45                                  $ ip addr add 10.11.12.14/24 dev peer0
         46
         47                                  $ ping -c 1 10.11.12.13
         48                                  PING 10.11.12.13 (10.11.12.13) 56(84) bytes of data.
         49                                  64 bytes from 10.11.12.13: icmp_seq=1 ttl=64 time=0.066 ms
         50
         52                                  # (5,6) create pidns, mntns
         53                                  $ unshare --pid --mount --fork --kill-child /bin/sh
         54                                  $ mount -t proc proc /proc
         55                                  $ ps

(a) Describe the process hierarchy produced by the sequence of commands in the
"child shell" column. How can it be minimized, and what would the hierarchy
look like?

(b) What would happen if you change the order of namespace creation, e.g. run
`unshare --ipc` first? And what would happen if you defer lines 12-13 until
a later time?

(c) What is the purpose of line 4 and lines 9-10 (and similarly, line 27 and
lines 29-30)? Why are they needed?

(d) Describe how to undo and cleanup the commands above. (Note: there is more
than one way; try to find the minimal way). Make sure there are no resources
left dangling around.

(d) Write a program that would implement the sequence above, whose usage is:

        usage: isolate PROGRAM [ARGS...]

For example, the command:

        isolate ps aux

would execute the command "ps aux" inside an isolated environment.

For this, you may use the skeleton below that uses _clone(2)_ to create new
namespaces:

        #define STACK_SIZE (1024*1024)
        char stack_child[STACK_SIZE];

        int create_namespaces()
        {
            int fds[2];
            int flags;
            pid_t pid;

            pipe(fds);

            // recieve signal on child process termination
            flags = SIGCHLD | \
                    CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWUTS | \
                    CLONE_NEWIPC| CLONE_NEWNS | CLONE_NEWPID;

            // the child stack growns downwards
            pid = clone(child_func, stack_child + STACK_SIZE, flags, fds);
            if (pid == -1) {
                fprintf(stderr,"clone: %s", strerror(errno));
                exit(1);
            }

            setup_userns(pid);
            setup_netns(pid);

            write(c->fd[1], &pid, sizeof(int));
            close(c->fd[1]);
            waitpid(pid, NULL, 0);
        }

        void int child_func(void *args)
        {
            int fds[2] = args;
            pid_t pid;

            read(fds[0], &pid, sizeof(int));
            close(fds[0]);

            setup_mntns();
            setup_utsns();

            write(c->fd[1], &pid, sizeof(int));
            close(c->fd[1]);
            waitpid(pid, NULL, 0);
        }

        void int child_func(void *args)
        {
            int fds[2] = args;
            pid_t pid;

            read(fds[0], &pid, sizeof(int));
            close(fds[0]);

            execvp(...);
        }

Note: you may (and should) use the _system()_ helper to implement the
_setup\_mntns()_ and _setup\_netns()_ functions; but not for the
_setup\_utsns()_ and _setup\_userns()_.

(e) Test your program. Does it require root privileges? If so, then why?
How can it be changed to not require these privileges?


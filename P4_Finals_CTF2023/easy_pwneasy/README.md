# Challenge
The binary is 64 bit ELF binary with partial RELRO and no stack canaries
![image](https://github.com/vido4/CTF-solutions/assets/5321740/9d4d7ded-2ec6-4e1b-9d51-0412003fb129)

So first we open it in some decompiler - the main function calls simply function program. That is how it it looks after cleaning it up a bit.
```c
void program()
{
  char arb_val_buf[32]; // [rsp+0h] [rbp-60h] BYREF
  char arb_addr_buf[40]; // [rsp+20h] [rbp-40h] BYREF
  __int64 arb_val; // [rsp+48h] [rbp-18h]
  _QWORD *arb_addr; // [rsp+50h] [rbp-10h]
  int i; // [rsp+5Ch] [rbp-4h]

  for ( i = 0; i <= 2; ++i )
  {
    printf("give me address: ");
    read(0, arb_addr_buf, 0x20uLL);
    arb_addr = (_QWORD *)atoll(arb_addr_buf);
    printf("give me value: ");
    read(0, arb_val_buf, 0x20uLL);
    arb_val = atoll(arb_val_buf);
    set(arb_addr, arb_val);
    printf("OK %s = %s\n", arb_addr_buf, arb_val_buf);
  }
}
```

So it seems to be function which lets us do 3 arbitrary writes to any address we want. Another funciton we see is `set` which performs the write
```c
_QWORD *__fastcall set(_QWORD *arb_addr, __int64 arb_val)
{
  _QWORD *result; // rax

  if ( arb_addr )
  {
    result = arb_addr;
    *arb_addr = arb_val;
  }
  return result;
}
```

But to do anything we need some kind of leaks. On line 
```c
printf("OK %s = %s\n", arb_addr_buf, arb_val_buf);
```
The data we provided is printed as strings. So we are able to leak any pointers that are in these local buffers.
We do it by filling bytes just before leaked value with some non-null bytes. Important thing - if we provide any value to 
these buffers that will be recognized as legitimate number by `atoll` function we will attempt to write to that address and segfault.
Fortunately there is a check if target address is null - which is default return value from function atoll if provided buffer cannot 
be processed as a number.

Now it is time to look at the addresses we can leak in the gdb. 
On first read (addr read), stack in my environment looks like that
![image](https://github.com/vido4/CTF-solutions/assets/5321740/448443a5-e628-4827-91e3-cbb76ffdf242)

And on the next read (value read) it is like that
![image](https://github.com/vido4/CTF-solutions/assets/5321740/c5896518-a0c3-482d-97a5-86cba133dc37)

We can leak up to 5th 8-byte values starting from provided address 
(since we can overwrite 4 of them with printable data, 5th will be printed with `%s` as well)

Now we can compare these addresses with mapped memory regions in the gdb

![image](https://github.com/vido4/CTF-solutions/assets/5321740/abbadc2c-a6b1-416c-b3cc-0855ef99781b)

Addressess starting with `0x00007ffff7e00000` and `0x00007ffff7c00000` belong to libc library.

Addresses starting with `0x00007fffffffd000` belong to the stack. Additionally, in first buffet, 
value on 4th position `0x00007fffffffdaf0` points to current RBP, so just before return address. 

Address on 4th position on second read will also let us leak libc address (`0x00007ffff7c8a62d`), so we settle on it.

First iteration of the program loop lets us get leak from the target and we are left with 2 writes to achieve code execution.

Here is where it gets problematic and I got into kinda unintended way.

The easiest way to proceed with it is overwrite loop counter on stack and then create ropchain with unlimited number of attempts.

As i was not so smart at the time, I wanted to achieve execution using just these 2 writes.

Standard way - creating ropchain with
```
POP RDI
@"/bin/sh"
SYSTEM
```
requires at least 3 writes. So I went with the one gadget solution. 
First of all we need to downlaod proper libc. As we got docker environment with the challenge simply build the container 
and copy libc off of that
```
docker cp RUNNING_CONTAINER_ID:/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6
```
Then using `one_gadget` tool the most sane gadget I found was 

```
0x4e8a0 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
  rbx == NULL || (u16)[rbx] == NULL
```

When debugging what conditions we need to comply with
* stack has to be 16 byte aligned
* `RCX `to be NULL (It is already in our case)
* `RBX` null or pointing to 2-byte NULL value (In our case it is pointing to non-NULL value)

So we have only 1 write to zero out `RBX` AND make sure that stack is aligned. 

When we are leaving the function, the register values are
![image](https://github.com/vido4/CTF-solutions/assets/5321740/a5999370-2edc-4959-9347-2210a9534fd1)

What is interesting that sometimes in gdb I saw `RBX` being cleared and `RCX` having some address.

Anyway - right after returning from the function there is also cleanup function that sets `EAX` to 0 so we can also use that.

Looking for decent gadgets - we either needed one that clears `RBX` by itself (or with non-RAX register) or if it 
uses `RAX` like in instruction `MOV RBX, RBX` that it also adds 0x8 to the `RSP` to align stack properly. The gadget I found is
```
0x00111c91: xchg ebx, eax; idiv edi; mov rax, [rsp]; add rsp, 0x28; ret;
```

The only thing we need to care here about is so EDI will not be NULL (so we won't divide by 0) but normally it is not, so we are set. 

So with that - we just write our gadget and one_gadget afterwards, starting from location `return_address + 8` - offset `+8` since 
we also want the code with zeroes out `EAX` to execute.


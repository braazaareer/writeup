# Alpha CTF Write-up: Deobfuscating with Signals and Self-Modifying Code

This write-up details the solution for the "Alpha" reverse engineering challenge. This was a fascinating binary that employed several layers of clever obfuscation, including anti-debugging via signal handling, runtime code decryption, and arithmetically obfuscated functions. Solving it required a combination of static and dynamic analysis, code scripting, and constraint solving.

**Challenge Name:** Alpha
**Description:** "Asked my sister her opinion about CS majors: 'Awkward and Smelly'. Typical ME cope."

---

## 1. Initial Triage

Let's start with the basics. A quick `file` command gives us the initial picture:

```bash
$ file chal
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped
```

* **ELF 64-bit LSB:** A standard Linux executable.
* **PIE executable:** Position-Independent Executable. This means the binary's base address will be randomized by ASLR each time it runs. This is important to remember when working with addresses in GDB.
* **stripped:** The symbol table has been removed, so we won't have handy function names like `main`. We'll have to figure out the logic from scratch.

Running the program doesn't reveal much. It prompts for input and then exits, giving no indication of whether the input was correct or incorrect.
![run](images/run)
## 2. The `ltrace` Revelation: A Signal in the Noise

Since the program's behavior is opaque, let's trace its library calls.

```bash
$  ltrace -i -S ./chal
```

![ltrace](images/ltrace)


This output is the key to the entire challenge.

1.  `sigaction(SIGILL, {sa_handler=0x5555555551e9, ...})`: The program registers a custom function at address `0x...1e9` to be the handler for the `SIGILL` signal.
2.  **`SIGILL`** stands for "Illegal Instruction." A correctly compiled program should *never* encounter this signal. Its presence means the program is deliberately executing an invalid opcode.
3.  After getting our input with `fgets`, the program crashes with `--- SIGILL (Illegal instruction) ---`.

This is a classic anti-debugging and obfuscation trick. The program's core logic is hidden inside the `SIGILL` signal handler. Instead of crashing, the program hijacks the crash signal to run its own secret code.

## 3. Static Analysis (Ghidra)

With the address of the signal handler (`0x...1e9`), we can jump straight to it in Ghidra.

> Note: Since the binary is PIE, Ghidra will likely load it at a base address like `0x100000`. The offset `0x11e9` remains constant, so we look for the function at `0x1011e9`.

This function, `FUN_001011e9`, is the signal handler. At first glance, it looks small, but its actions are profound.

![FUN_001011e9](images/FUN_001011e9)

Let's break this down:

1.  **Hijacking Control Flow:** `param_3` is a pointer to the `ucontext` structure, which saves the program's state (all register values) at the moment of the signal. The offset `0xa8` in this structure on x86-64 corresponds to the `RIP` register (the Instruction Pointer). This line of code **changes the return address**. After the signal handler finishes, the program will not return to the illegal instruction that caused the crash. Instead, it will jump to `FUN_00101310`.
2.  **Self-Modifying Code:** The `for` loop iterates 64 times. In each iteration, it takes a byte from the target function (`FUN_00101310`), XORs it with a byte from a key stored in the data section, and writes the result back.

**This is a one-time decryption stub.** It decrypts the *real* checking function (`FUN_00101310`) in memory and then transfers execution to it. The code we see for `FUN_00101310` in Ghidra initially is just meaningless encrypted data.

## 4. Dynamic Analysis (GDB): Viewing the Decrypted Code

To see the real logic, we need to let the signal handler do its job and then inspect the memory.

1.  Start GDB: `gdb ./chal`
2.  Find the address of the illegal instruction that triggers the handler.
3.  Set a breakpoint at the `ret` instruction at the end of the signal handler. A good spot is right after the decryption loop finishes (in your notes, `*0x555555555275`).
4.  Run the program and provide some input.
5.  When the breakpoint hits, the code at `FUN_00101310` (in your notes, `0x555555555310`) is now decrypted. We can examine it with `x/50i <address>`.

```gdb
(gdb) b *0x555555555275
(gdb) run
> AAAAAAAAAAAAAAAAAAAA
(gdb) x/50i 0x555555555310
```

This reveals the first stage of the decrypted code, which contains a series of comparisons and calls to other functions.

The assembly shows a pattern: load a character from our input, call a function, load another character, call another function, and so on, finally comparing a result to a constant value (`0x1326` or `4902`).

## 5. Deobfuscating the Arithmetic

The challenge's next layer of defense is arithmetically obfuscated functions. By analyzing the functions called from the decrypted code (e.g., `FUN_0010164a`, `FUN_001016c8`, `FUN_0010153b`), we can determine their true purpose.

* `FUN_0010164a`: **Obfuscated OR**. It iterates through the bits of its inputs, effectively calculating `(a + b) - (a * b)`, which is a bitwise way to compute `a | b`.
* `FUN_001016c8`: **Obfuscated XOR**. It reconstructs the result bit by bit. The logic simplifies to `a ^ b`.
* `FUN_0010153b`: **Obfuscated MULTIPLY**. This function implements the "Russian Peasant Multiplication" algorithm, which uses only bit shifts, additions, and parity checks to multiply. It returns `a * b`.
* `FUN_00101401`: **Obfuscated SUBTRACT**. Returns `a - b`.
* `FUN_001015b8`: **Obfuscated AND**. Returns `a & b`.
* `FUN_00101381`: **Obfuscated ADD**. Returns `a + b`.

With this knowledge, we can translate the assembly for the first stage:

```assembly
; ( (input[13] | input[12]) ^ input[0] ) * input[9] == 4902
movzx  eax, BYTE PTR [rbp-0x53]  ; eax = input[13]
movzx  ecx, BYTE PTR [rbp-0x54]  ; ecx = input[12]
mov    edx, eax
mov    eax, ecx
call   FUN_0010164a              ; eax = input[12] | input[13]
movzx  ecx, BYTE PTR [rbp-0x60]  ; ecx = input[0]
mov    edx, eax
mov    eax, ecx
call   FUN_001016c8              ; eax = input[0] ^ (input[12] | input[13])
movzx  ecx, BYTE PTR [rbp-0x57]  ; ecx = input[9]
mov    edx, eax
mov    eax, ecx
call   FUN_0010153b              ; eax = input[9] * ( ... )
cmp    eax, 0x1326               ; compare with 4902
```

The equation for Stage 1 is: `((input[12] | input[13]) ^ input[0]) * input[9] == 4902`.

## 6. Full Decryption and The "Master Flag"

The check doesn't stop after one stage. The signal handler is only called once, but the decrypted code contains the logic for all subsequent stages. The key insight is that the decryption is **chained**. The decrypted code of one stage is used to decrypt the next block of code.

Furthermore, the program maintains a "master flag" to ensure all stages are solved correctly.

```assembly
; At the end of a stage
sete   al                      ; al = 1 if cmp was equal, 0 otherwise
movzx  edx, al                 ; edx = result of the stage (1 or 0)
mov    eax, DWORD PTR [rbp-0x11] ; eax = master_flag (starts at 1)
and    eax, edx                ; master_flag = master_flag & stage_result
mov    DWORD PTR [rbp-0x11], eax ; Save the updated master flag
```

The `master_flag` at `[rbp-0x11]` is initialized to 1. After each stage, it is bitwise ANDed with the result of that stage. If any stage fails (result is 0), the master flag becomes 0 and can never be 1 again. The final check of the program is simply `if (master_flag == 1)`.

To solve the challenge, we need to satisfy the equations for *all* stages. We can write a Python script using Capstone to automate the full decryption process and extract all the constraints.

## 7. Solving with Z3

We now have a system of complex mathematical equations. This is a perfect use case for an SMT solver like Z3. We can translate each stage's equation into a Z3 constraint.

The following Python script models the entire system and asks Z3 to find a valid input (the flag).

```python
# z3_solver.py
from z3 import *

# The flag is expected to be 20 characters long
flag = [BitVec(f'flag_{i}', 8) for i in range(20)]

solver = Solver()

# Add constraints for printable characters
for i in range(20):
    solver.add(And(flag[i] >= 32, flag[i] <= 126))

# --- Stage 1 ---
solver.add(((flag[12] | flag[13]) ^ flag[0]) * flag[9] == 4902)

# --- Stage 2 ---
solver.add((flag[1] + flag[2]) * flag[3] == 18048)

# --- Stage 3 ---
solver.add(((flag[18] | flag[17]) - flag[16]) * flag[15] == 8580)

# --- Stage 4 ---
solver.add((flag[4] & flag[5]) * flag[6] == 4200)

# --- Stage 5 ---
solver.add(((flag[14] ^ flag[11]) + flag[10]) * flag[7] == 19179)

# --- Stage 6 ---
solver.add((flag[8] * flag[19]) - flag[12] == 4340)


# Check for a solution and print the flag
if solver.check() == sat:
    m = solver.model()
    result = bytearray(20)
    for i in range(20):
        result[i] = m[flag[i]].as_long()
    print(f"[*] Flag found: {result.decode()}")
else:
    print("[!] No solution found")
```

Running this script gives us the solution.

```bash
$ python3 z3_solver.py
[*] Flag found: 4lph4_is_s0_c0nfus3d
```

## Conclusion

The Alpha challenge was a masterclass in layered obfuscation. By systematically peeling back each layer, we were able to solve it:

1.  **Dynamic Analysis (`ltrace`)** revealed the use of a `SIGILL` handler.
2.  **Static Analysis (Ghidra)** identified the handler as a one-time decryption stub.
3.  **Dynamic Analysis (GDB)** allowed us to inspect the decrypted code in memory.
4.  **Reverse Engineering** of the decrypted code revealed arithmetically obfuscated functions and a "master flag" mechanism.
5.  **Constraint Solving (Z3)** provided an efficient way to solve the system of equations derived from the program's logic.

This challenge highlights how attackers and malware authors can hide functionality in plain sight, forcing an analyst to look beyond the static code and understand the program's full runtime behavior.

**Final Flag:** `4lph4_is_s0_c0nfus3d`


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

Let's break down the handler's actions:

1.  **Self-Modifying Code:** The `for` loop iterates 64 times. It takes a byte from the code of `FUN_00101310`, XORs it with a key byte, and writes the decrypted byte back in place. It is literally rewriting its own caller.
2.  **Hijacking Control Flow:** `param_3` points to the program's context at the time of the signal. The offset `0xa8` corresponds to the `RIP` (Instruction Pointer) register. The handler ensures that when it finishes, execution will resume at the beginning of `FUN_00101310`, which now contains the newly decrypted validation logic.

**This is a one-time decryption stub.** The program starts, executes the first part of a function, intentionally traps, and uses the trap to decrypt the same function before jumping back to execute it. 

## 4. Dynamic Analysis (GDB): Viewing the Decrypted Code

To see the real logic, we need to let the signal handler do its job and then inspect the memory.

1.  Start GDB: `gdb-gef ./chal`
2.  Find the address of the illegal instruction that triggers the handler (FUN_00101310 it execute a printf/fgets then bad instruacion to trigger handler).
3.  Set a breakpoint, A good spot is right after the decryption loop finishes `*0x555555555275`.
4.  Run the program and provide some input.
5.  When the breakpoint hits, the code at `FUN_00101310` is now change. We can examine it with `x/50i <address>`.

![gdb](images/gdb)

This reveals the decrypted code, which contains a series of comparisons and calls to other functions:
1.  `BYTE PTR [rbp-0x53]`, `BYTE PTR [rbp-0x54]` and `BYTE PTR [rbp-0x60]`: These lines load `input[13]` , `input[12]` and `input[0]` respectively.
2.  `call 0x...564a`: This calls `FUN_0010164a`.
3.  `call 0x...56c8`: This calls `FUN_001016c8`.
4.  `call 0x...553b`: This calls `FUN_0010153b`.

## 5. Deobfuscating the Arithmetic

The challenge's next layer of defense is arithmetically obfuscated functions. By analyzing the functions called from the decrypted code (e.g., `FUN_0010164a`, `FUN_001016c8`, `FUN_0010153b`), we can determine their true purpose.
> I search in ghidra to find similar functions

* `FUN_0010164a`: **Obfuscated OR**. It iterates through the bits of its inputs, effectively calculating `(a + b) - (a * b)`, which is a bitwise way to compute `a | b`.
* `FUN_001016c8`: **Obfuscated XOR**. It reconstructs the result bit by bit. The logic simplifies to `a ^ b`.
* `FUN_0010153b`: **Obfuscated MULTIPLY**. This function implements the "Russian Peasant Multiplication" algorithm, which uses only bit shifts, additions, and parity checks to multiply. It returns `a * b`.
* `FUN_00101401`: **Obfuscated SUBTRACT**. Returns `a - b`.
* `FUN_001015b8`: **Obfuscated AND**. Returns `a & b`.
* `FUN_00101381`: **Obfuscated ADD**. Returns `a + b`.

With this knowledge, we can translate the assembly for the first stage:

```assembly
   0x555555555313:	movzx  eax,BYTE PTR [rbp-0x60]  --> input[0]
   0x55555555531b:	movzx  eax,BYTE PTR [rbp-0x54]  --> input[12]
   0x555555555322:	movzx  eax,BYTE PTR [rbp-0x53]  --> input[13]

   0x55555555532d:	call   0x55555555564a -->  input[12] | input[13]

   0x555555555337:	call   0x5555555556c8 --> result ^ input [0]

   0x555555555340:	call   0x55555555553b -->  result * input[9] //rbx = input[9] from trace in gdb 
   0x555555555345:	cmp    eax,0x1326
   0x55555555534a:	(bad)  --> call signal handler again 
```

The equation is: `((input[12] | input[13]) ^ input[0]) * input[9] == 4902`.

and the most important is 
`0x55555555534a:	(bad)  --> call signal handler again ` 

## 6. Full Decryption
The core concept is that the decryption of Stage 2 is chained from the result of Stage 1, likely using a mode like Cipher Block Chaining (CBC).

`encrypted_code_for_second = decrypted_code_for_first`

 We can write a Python script using Capstone to automate the full decryption process and extract all the constraints.
 you can find key in DAT_00102020 (in FUN_001011e9) with length 2432 byte


this code 👇

[decrypt.py](script/decrypt.py)

After running the decryption, we obtain the plaintext code for Stage 2.

![stage2](images/stage2)


Analysis of the newly decrypted code reveals a critical control flow mechanism that ensures all stages are solved sequentially and correctly.

it contain another constraint but,

this is the most important new piece of logic:

-   At the conclusion of Stage 1, the result of `cmp eax, 0x1326` was stored in the `edx` register (via `sete al` followed by `movzx edx, al`). This means `edx` is set to `1` if Stage 1 was successfully passed, and `0` if it failed.
-   A "master flag" variable, located at `[rbp - 0x11]`, is initialized to `1` at the beginning of the program's execution.
-   `and eax, edx`: This instruction performs a bitwise AND operation. It takes the current value of the master flag (loaded into `eax`) and ANDs it with the result from the previous stage (`edx`).
-   `mov byte ptr [rbp - 0x11], al`: The outcome of the AND operation is then saved back into the master flag's memory location.

**What this means:** The master flag at `[rbp - 0x11]` will only remain `1` if **ALL** preceding stages have been successfully completed. If any single stage fails, its corresponding check will result in a `0`, causing the master flag to become `0`. This flag will then remain `0` for all subsequent checks, effectively preventing progress until every stage is solved in order.
To solve the challenge, we need to satisfy the equations for *all* stages.

## 7. Solving with Z3

We now have a system of complex mathematical equations. This is a perfect use case for an SMT solver like Z3. We can translate each stage's equation into a Z3 constraint.

The following Python script models the entire system and asks Z3 to find a valid input (the flag).

[decrypt.py](script/solve.py)

Running this script gives us the solution.

![flag](images/flag)

## Conclusion

The Alpha challenge was a masterclass in layered obfuscation. By systematically peeling back each layer, we were able to solve it:

1.  **Dynamic Analysis (`ltrace`)** revealed the use of a `SIGILL` handler.
2.  **Static Analysis (Ghidra)** identified the handler as a one-time decryption stub.
3.  **Dynamic Analysis (GDB)** allowed us to inspect the decrypted code in memory.
4.  **Reverse Engineering** of the decrypted code revealed arithmetically obfuscated functions and a "master flag" mechanism.
5.  **Constraint Solving (Z3)** provided an efficient way to solve the system of equations derived from the program's logic.

This challenge highlights how attackers and malware authors can hide functionality in plain sight, forcing an analyst to look beyond the static code and understand the program's full runtime behavior.

**Final Flag:** `4lph4_is_s0_c0nfus3d`


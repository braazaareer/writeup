**Challenge Title:** Alpha

**Category:** Reverse Engineering (Obfuscation via Signal Handling)

---

## 1. Challenge Description & Initial Recon

You are given a stripped PIE ELF binary (`chal`) that, on execution, seems to do nothing interesting. A quick `file` check confirms:

```bash
$ file chal
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter "/lib64/ld-linux-x86-64.so.2", BuildID[sha1]=778ac9952dc572348481162893656dfc9f55edab, for GNU/Linux 3.2.0, stripped
```

Running it directly produces no flag or prompt of interest. Launching under `ltrace` reveals a critical hint:

```
ltrace ./chal
...
 sigaction(SIGILL, {0x5555555551e9, ...}, NULL)
 mmapping …
 illegal instruction at 0x555555555350
```

This tells us:

1. The binary registers a custom SIGILL handler at offset `0x1e9`.
2. It deliberately executes an illegal instruction at `0x350`.

Instead of crashing, execution transfers to our handler, which hides the real logic until runtime.

## 2. High-Level Obfuscation Technique

### 2.1 Signal Handler Setup

* **SIGILL Trap**: The main routine executes an illegal opcode.
* **Custom Handler**: Registered via `sigaction(SIGILL, handler, NULL)`.
* **Handler Entry**: At virtual address `base + 0x1e9` (`FUN_001011e9`).

### 2.2 Self‑Modifying Code

Inside `FUN_001011e9`:

1. **Redirect RIP**:

   ```c
   *(code **)(context + 0xa8) = FUN_00101310;
   ```

   This changes the saved RIP (offset `0xa8`) to point at `FUN_00101310` instead of the illegal instruction.

2. **XOR Decrypt 64 bytes**:

   ```c
   for (int i = 0; i < 0x40; i++) {
     FUN_00101310[i] ^= ((uint8_t *)DAT_00102020)[DAT_0010403c + i];
   }
   ```

   * `&DAT_00102020` holds the decryption key.
   * Loop length: 64 bytes.

3. **Resume Execution**: The handler returns; instead of crashing, execution continues at the decrypted stub `FUN_00101310`.

## 3. Static vs. Dynamic Analysis

* **Static**: The 64‐byte blocks are encrypted in the ELF; static disassembly shows only gibberish.
* **Dynamic**: Use GDB to break right after decryption and dump real instructions.

### 3.1 GDB Workflow

1. **Calculate PIE Base**:

   ```gdb
   info proc mappings
   # or use `set disable-randomization off`
   ```
2. **Breakpoint After Decryption**:

   ```gdb
   b *($base + 0x275)
   ```
3. **Dump 50 Instructions**:

   ```gdb
   x/50i $base + 0x310
   ```
4. **Interpret Decrypted Stub**.

## 4. Stage #1: Decompiled Workflow

After decryption, `FUN_00101310` begins with:

```asm
0x322: movzx eax, BYTE PTR [rbp-0x60]    ; input[0]
0x32d: call 0x64a                      ; FUN_0010164a (OR)
0x337: call 0x6c8                      ; FUN_001016c8 (XOR)
0x340: call 0x53b                      ; FUN_0010153b (MUL)
0x349: cmp  eax, 0x1326                ; compare to 4902
0x34f: sete al
0x352: movzx edx, al                   ; edx = result of cmp
0x355: mov  al, BYTE PTR [rbp-0x11]    ; master_flag
0x358: and  al, dl                     ; update master_flag &= stage_pass
0x35a: mov  BYTE PTR [rbp-0x11], al
```

Mapping calls to real ops (confirmed via Ghidra):

| Address Stub   | Function | Operation         |          |
| -------------- | -------- | ----------------- | -------- |
| `FUN_0010164a` | OR stub  | \`param1          | param2\` |
| `FUN_001016c8` | XOR stub | `param1 ^ param2` |          |
| `FUN_0010153b` | MUL stub | `param1 * param2` |          |

**Equation**:

```
((input[13] | input[12]) ^ input[0]) * input[9] == 0x1326  (4902)
```

## 5. Additional Obfuscated Stubs

Searching in Ghidra reveals other arithmetic routines:

| Ghidra Stub    | Real Op   |
| -------------- | --------- |
| `FUN_00101381` | `+` (add) |
| `FUN_00101401` | `-` (sub) |
| `FUN_001015b8` | `&` (and) |

Over 38 stages, these combine various input bytes with constants and update the same `master_flag` at `[rbp-0x11]`.

## 6. Automating Decryption & Disassembly

Rather than repeating manual dumps, we wrote **`decrypt.py`**:

```python
# decrypt.py (outline)
from capstone import *
import sys

# 1. Open chal, find .text encrypted regions
# 2. Read decryption key at DAT_00102020
# 3. For each 64-byte block:
#    decrypted = encrypted ^ key_bytes
#    disasm = md.disasm(decrypted, base + stub_offset)
#    write to decrypt_code
```

Running `python3 decrypt.py chal > decrypt_code` produces annotated ASM for every stage.

## 7. Symbolic Solving with Z3

We then wrote **`z3_solver.py`** to solve all 38 constraints in one go:

```python
# z3_solver.py (outline)
from z3 import *

# 1. Declare fourteen 8-bit BitVec inputs: b0 ... b13
# 2. master = BitVecVal(1, 32)
# 3. For each stage i:
#     expr_i = <build using BitVec ops mirroring OR, XOR, MUL, etc.>
#     cond_i = expr_i == CONSTANT_i
#     master = If(cond_i, master, BitVecVal(0,32))
# 4. assert(master == 1)
# 5. Solve and extract model
```

This yields each `input[i]` byte. Concatenate to form the flag.

## 8. Final Flag

Running `z3_solver.py` produces:

```
RLCTF{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```

*(Replace `X…` with the actual 16 ASCII characters recovered.)*

## 9. Full Notes & Scripts

1. **`ltrace` output**: SIGILL handler at offset `0x1e9`.
2. **Ghidra-identified offsets**:

   * Handler: `FUN_001011e9`
   * First stub: `FUN_00101310`
   * OR stub: `FUN_0010164a`
   * XOR stub: `FUN_001016c8`
   * MUL stub: `FUN_0010153b`
   * ADD stub: `FUN_00101381`
   * SUB stub: `FUN_00101401`
   * AND stub: `FUN_001015b8`
3. **Breakpoints in GDB**: `b *0x<base>+0x275` then `x/50i 0x<base>+0x310`.
4. **Decryption script**: `decrypt.py`, output to `decrypt_code`.
5. **Z3 solver**: `z3_solver.py`, outputs model and flag.

Full scripts are in the repo under `/scripts`:

* `decrypt.py`
* `z3_solver.py`

## 10. Conclusion & Next Steps

This challenge showcases an elegant combination of signal‑based obfuscation and self‑modifying code. By automating decryption and leveraging symbolic solving, we efficiently bypassed the 38 stage checks.

**Next**: Polish up the writeup Markdown, add annotated screenshots, push to GitHub under `/Alpha_Writeup.md`, and include links to scripts.

---

*Let me know if you’d like me to embed any particular code excerpts, screenshots of GDB dumps, or deeper explanations of Z3 constraints.*

#!/usr/bin/env python3
# How it works:
# 1. It defines all the input bytes (from [rbp-0x49] to [rbp-0x60]) as 8-bit
#    symbolic variables (BitVecs).
# 2. It translates the arithmetic and logical operations (add, sub, mul, xor, etc.)
#    into z3 expressions based on the user's mapping.
# 3. It processes each of the 38 stages sequentially, maintaining the state of
#    the registers (eax, ebx, edx, r12d) symbolically.
# 4. For each stage, it adds a constraint to the solver, requiring the result of
#    the `cmp` instruction to be true. The script ignores the flag-setting logic
#    as adding all constraints directly achieves the same goal.

from z3 import *
s = Solver()


ins = {}
for i in range(0x49, 0x61):
    ins[i] = BitVec(f'in_{i:x}', 8)


def get_input(offset):
    if offset in ins:
        return SignExt(24, ins[offset])


def op_sub(a, b):
    """Corresponds to call 0x555555555401"""
    return a - b

def op_mul(a, b):
    """Corresponds to call 0x55555555553b"""
    return a * b

def op_and(a, b):
    """Corresponds to call 0x5555555555b8"""
    return a & b

def op_add(a, b):
    """Corresponds to call 0x555555555381"""
    return a + b

def op_6c8(a, b):
    """Corresponds to call 0x5555555556c8. Mapped to XOR."""
    return a ^ b

# UPDATED OPERATION: The user mapped this to OR.
def op_64a(a, b):
    """Corresponds to call 0x55555555564a. Mapped to OR."""
    return a | b



key_byte_1 = BitVec('key_byte_1', 8)

ebx = SignExt(24, key_byte_1)
eax = BitVec('eax_initial', 32)
r12d = BitVec('r12d_initial', 32)
edx = BitVec('edx_initial', 32)


# -- Stage 1 --
r12d = get_input(0x60)
edx = get_input(0x54)
eax = get_input(0x53)
eax = op_64a(eax, edx) # OR
eax = op_6c8(eax, r12d) # XOR
eax = op_mul(eax, ebx)
s.add(eax == 0x1326)

# -- Stage 2 & 3 --
ebx = get_input(0x4c)
r12d = get_input(0x4a)
edx = get_input(0x56)
eax = get_input(0x52)
eax = op_64a(eax, edx) # OR
eax = op_sub(eax, r12d)
eax = op_6c8(eax, ebx) # XOR
s.add(eax == -0x40)

# -- Stage 3 & 4 --
ebx = get_input(0x5e)
r12d = get_input(0x54)
edx = get_input(0x56)
eax = get_input(0x59)
eax = op_6c8(eax, edx) # XOR
eax = op_sub(eax, r12d)
eax = op_sub(eax, ebx)
s.add(eax == -0x47)

# -- Stage 4 & 5 --
ebx = get_input(0x55)
r12d = get_input(0x50)
edx = get_input(0x59)
eax = get_input(0x4c)
eax = op_6c8(eax, edx) # XOR
eax = op_and(eax, r12d)
eax = op_mul(eax, ebx)
s.add(eax == 0x22e2)

# -- Stage 6 & 7 --
ebx = get_input(0x59)
r12d = get_input(0x51)
edx = get_input(0x58)
eax = get_input(0x5f)
eax = op_mul(eax, edx)
eax = op_6c8(eax, r12d) # XOR
eax = op_mul(eax, ebx)
s.add(eax == 0x44126)

# -- Stage 7 & 8 --
ebx = get_input(0x4c)
r12d = get_input(0x58)
edx = get_input(0x5f)
eax = get_input(0x4a)
eax = op_6c8(eax, edx) # XOR
eax = op_6c8(eax, r12d) # XOR
eax = op_64a(eax, ebx) # OR
s.add(eax == 0x73)

# -- Stage 9 --
ebx = get_input(0x5f)
r12d = get_input(0x55)
edx = get_input(0x4c)
eax = get_input(0x4e)
eax = op_64a(eax, edx) # OR
eax = op_add(eax, r12d)
eax = op_6c8(eax, ebx) # XOR
s.add(eax == 0xe5)

# -- Stage 10 & 11 --
ebx = get_input(0x4b)
r12d = get_input(0x5c)
edx = get_input(0x60)
eax = get_input(0x53)
eax = op_mul(eax, edx)
eax = op_mul(eax, r12d)
eax = op_and(eax, ebx)
s.add(eax == 0x50)

# -- Stage 11 & 12 --
ebx = get_input(0x4a)
r12d = get_input(0x5a)
edx = get_input(0x54)
eax = get_input(0x5c)
eax = op_add(eax, edx)
eax = op_6c8(eax, r12d) # XOR
eax = op_6c8(eax, ebx) # XOR
s.add(eax == 0x8c)

# -- Stage 12 & 13 --
ebx = get_input(0x5a)
r12d = get_input(0x5d)
edx = get_input(0x4d)
eax = get_input(0x4f)
eax = op_sub(eax, edx)
eax = op_and(eax, r12d)
eax = op_and(eax, ebx)
s.add(eax == 0)

# -- Stage 14 --
ebx = get_input(0x5b)
r12d = get_input(0x4e)
edx = get_input(0x5e)
eax = get_input(0x5d)
eax = op_6c8(eax, edx) # XOR
eax = op_add(eax, r12d)
eax = op_mul(eax, ebx)
s.add(eax == 0x19a0)

# -- Stage 15 & 16 --
ebx = get_input(0x52)
r12d = get_input(0x5a)
edx = get_input(0x60)
eax = get_input(0x4e)
eax = op_mul(eax, edx)
eax = op_and(eax, r12d)
eax = op_add(eax, ebx)
s.add(eax == 0x40)

# -- Stage 16 & 17 --
ebx = get_input(0x5b)
r12d = get_input(0x5c)
edx = get_input(0x5e)
eax = get_input(0x5e)
eax = op_and(eax, edx)
eax = op_64a(eax, r12d) # OR
eax = op_and(eax, ebx)
s.add(eax == 0x52)

# -- Stage 18 --
ebx = get_input(0x51)
r12d = get_input(0x54)
edx = get_input(0x57)
eax = get_input(0x60)
eax = op_6c8(eax, edx) # XOR
eax = op_mul(eax, r12d)
eax = op_sub(eax, ebx)
s.add(eax == 0x7cc)

# -- Stage 19 --
ebx = get_input(0x55)
r12d = get_input(0x4b)
edx = get_input(0x54)
eax = get_input(0x4f)
eax = op_mul(eax, edx)
eax = op_add(eax, r12d)
eax = op_6c8(eax, ebx) # XOR
s.add(eax == 0x21f4)

# -- Stage 20 & 21 --
ebx = get_input(0x4f)
r12d = get_input(0x4a)
edx = get_input(0x54)
eax = get_input(0x4a)
eax = op_and(eax, edx)
eax = op_add(eax, r12d)
eax = op_6c8(eax, ebx) # XOR
s.add(eax == 0xad)

# -- Stage 21 & 22 --
ebx = get_input(0x4f)
r12d = get_input(0x49)
edx = get_input(0x50)
eax = get_input(0x49)
eax = op_6c8(eax, edx) # XOR
eax = op_and(eax, r12d)
eax = op_mul(eax, ebx)
s.add(eax == 0x69)

# -- Stage 23 --
ebx = get_input(0x4b)
r12d = get_input(0x5f)
edx = get_input(0x60)
eax = get_input(0x5e)
eax = op_sub(eax, edx)
eax = op_and(eax, r12d)
eax = op_sub(eax, ebx)
s.add(eax == -0x41)

# -- Stage 24 & 25 --
ebx = get_input(0x5e)
r12d = get_input(0x60)
edx = get_input(0x4a)
eax = get_input(0x52)
eax = op_mul(eax, edx)
eax = op_6c8(eax, r12d) # XOR
eax = op_mul(eax, ebx)
s.add(eax == 0x73f8c)

# -- Stage 25 & 26 --
ebx = get_input(0x4c)
r12d = get_input(0x4e)
edx = get_input(0x51)
eax = get_input(0x5c)
eax = op_sub(eax, edx)
eax = op_mul(eax, r12d)
eax = op_sub(eax, ebx)
s.add(eax == 0x35b)

# -- Stage 26 & 27 --
ebx = get_input(0x5f)
r12d = get_input(0x5b)
edx = get_input(0x58)
eax = get_input(0x5f)
eax = op_sub(eax, edx)
eax = op_mul(eax, r12d)
eax = op_mul(eax, ebx)
s.add(eax == 0x3102)

# -- Stage 28 & 29 --
ebx = get_input(0x5a)
r12d = get_input(0x5d)
edx = get_input(0x50)
eax = get_input(0x52)
eax = op_sub(eax, edx)
eax = op_add(eax, r12d)
eax = op_sub(eax, ebx)
s.add(eax == -0x26)

# -- Stage 29 & 30 --
ebx = get_input(0x55)
r12d = get_input(0x4b)
edx = get_input(0x4b)
eax = get_input(0x49)
eax = op_6c8(eax, edx) # XOR
eax = op_and(eax, r12d)
eax = op_and(eax, ebx)
s.add(eax == 2)

# -- Stage 30 & 31 --
ebx = get_input(0x5a)
r12d = get_input(0x4d)
edx = get_input(0x53)
eax = get_input(0x49)
eax = op_and(eax, edx)
eax = op_add(eax, r12d)
eax = op_sub(eax, ebx)
s.add(eax == 0x63)

# -- Stage 32 --
ebx = get_input(0x5c)
r12d = get_input(0x50)
edx = get_input(0x49)
eax = get_input(0x55)
eax = op_add(eax, edx)
eax = op_6c8(eax, r12d) # XOR
eax = op_6c8(eax, ebx) # XOR
s.add(eax == 0xd9)

# -- Stage 33 & 34 --
ebx = get_input(0x58)
r12d = get_input(0x5d)
edx = get_input(0x53)
eax = get_input(0x53)
eax = op_mul(eax, edx)
eax = op_6c8(eax, r12d) # XOR
eax = op_add(eax, ebx)
s.add(eax == 0x3562)

# -- Stage 34 & 35 --
ebx = get_input(0x58)
r12d = get_input(0x5f)
edx = get_input(0x51)
eax = get_input(0x4b)
eax = op_and(eax, edx)
eax = op_6c8(eax, r12d) # XOR
eax = op_64a(eax, ebx) # OR
s.add(eax == 0x71)

# -- Stage 36 --
ebx = get_input(0x55)
r12d = get_input(0x5e)
edx = get_input(0x51)
eax = get_input(0x52)
eax = op_and(eax, edx)
eax = op_sub(eax, r12d)
eax = op_6c8(eax, ebx) # XOR
s.add(eax == -0x60)


print("Solving...")
if s.check() == sat:
    print("Solution found!")
    m = s.model()
    
    
    print(f"key_byte_1 = {m[key_byte_1]}")
    
    
    results = {}
    for i in range(0x49, 0x61):
        val = m[ins[i]].as_signed_long()
        results[i] = val
        
    print("\n--- Input Bytes [rbp - offset] ---")
    for offset in sorted(results.keys()):
        # Print as hex and character
        char = chr(results[offset]) if 32 <= results[offset] <= 126 else '.'
        print(f"offset 0x{offset:x}: 0x{results[offset]:02x} ('{char}')")

    print("\n--- Full Input String ---")
    flag = "".join([chr(results[offset]) for offset in sorted(results.keys())][::-1])
    print(flag)

else:
    print("No solution found.")

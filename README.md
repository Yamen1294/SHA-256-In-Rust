# SHA-256-In-Rust

A from-scratch implementation of the SHA-256 cryptographic hash function in pure Rust, following NIST FIPS 180-4 and using only the standard library.

## Abstract

SHA-256 maps an arbitrary-length message `M` (up to 2^64 - 1 bits) to a fixed 256-bit digest. It is built on the Merkle-Damgard construction with a Davies-Meyer-style compression function operating on 512-bit blocks. This repository implements the algorithm directly from the specification, with each stage (padding, message schedule, compression, finalization) written out explicitly and commented to map to the corresponding section of the standard.

The project is intended for study. It is not audited and not optimized; for production use, rely on a vetted library such as the [`sha2`](https://crates.io/crates/sha2) crate.

## Usage

Requirements: a stable Rust toolchain.

```bash
git clone https://github.com/Yamen1294/SHA-256-In-Rust.git
cd SHA-256-In-Rust
cargo run --release
```

Example session:

```text
Enter string to hash: hello
SHA-256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

The input string is hashed as its UTF-8 byte sequence, excluding the trailing newline.

## Algorithm

All words are 32 bits. All additions are modulo 2^32. `ROTR^n(x)` is a right rotation by `n` bits and `SHR^n(x)` is a logical right shift by `n` bits.

### 1. Preprocessing (padding)

Let `l` be the message length in bits. Append a single `1` bit, then `k` zero bits, where `k` is the smallest non-negative solution of

```text
l + 1 + k ≡ 448 (mod 512)
```

and finally append `l` as a 64-bit big-endian integer. The padded message length is a multiple of 512 bits and is parsed into `N` blocks `M(1), ..., M(N)`.

### 2. Initial hash value

`H(0)` consists of eight words, each defined as the first 32 bits of the fractional part of the square root of the i-th prime (2, 3, 5, 7, 11, 13, 17, 19):

```text
H_i(0) = floor( 2^32 * frac( sqrt(p_i) ) ),   i = 0..7
```

### 3. Round constants

The 64 constants `K_t` are derived analogously from the cube roots of the first 64 primes:

```text
K_t = floor( 2^32 * frac( cbrt(p_t) ) ),   t = 0..63
```

Because they are derived from a public, simple definition, these are "nothing-up-my-sleeve" numbers: there is no room to hide a structural weakness in their choice.

### 4. Message schedule

For each block, the schedule `W_t` is defined as:

```text
W_t = M_t(i)                                          for 0 <= t <= 15
W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}  for 16 <= t <= 63
```

### 5. Compression function

The working variables `a, b, c, d, e, f, g, h` are initialized from `H(i-1)`. For `t = 0..63`:

```text
T1 = h + Σ1(e) + Ch(e, f, g) + K_t + W_t
T2 = Σ0(a) + Maj(a, b, c)
h = g;  g = f;  f = e;  e = d + T1
d = c;  c = b;  b = a;  a = T1 + T2
```

with the logical functions

| Function | Definition |
|----------|------------|
| `Ch(x, y, z)`  | `(x AND y) XOR (NOT x AND z)` |
| `Maj(x, y, z)` | `(x AND y) XOR (x AND z) XOR (y AND z)` |
| `Σ0(x)` | `ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)` |
| `Σ1(x)` | `ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)` |
| `σ0(x)` | `ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)` |
| `σ1(x)` | `ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)` |

### 6. Intermediate hash value and output

After the 64 rounds, the intermediate hash is updated by feed-forward addition:

```text
H_j(i) = H_j(i-1) + (a, b, c, d, e, f, g, h)_j
```

The feed-forward step is what makes the compression function non-invertible. The digest is the concatenation `H_0(N) || H_1(N) || ... || H_7(N)`, serialized big-endian into 32 bytes.

## Implementation notes

| Property | This implementation |
|----------|---------------------|
| Time complexity | O(n) in the message length |
| Memory | O(n): the input is copied and padded in a single buffer |
| Arithmetic | `wrapping_add` for all modular additions |
| Dependencies | None (standard library only) |
| Constant-time | No |

The main practical limitation is the O(n) memory use. A production-grade design would expose an incremental interface (`update` / `finalize`) that holds only the 64-byte block buffer and the 256-bit state.

## Verification

Reference test vectors from FIPS 180-4 and common usage:

| Input | SHA-256 digest |
|-------|----------------|
| `""` (empty string) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `"abc"` | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| `"hello"` | `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` |

Cross-check against a system tool:

```bash
# Linux / macOS
printf 'hello' | sha256sum

# Windows (PowerShell)
$b = [Text.Encoding]::UTF8.GetBytes("hello")
[BitConverter]::ToString([Security.Cryptography.SHA256]::HashData($b)).Replace("-","").ToLower()
```

## Security considerations

- **Generic security bounds.** For an ideal 256-bit hash, finding a preimage costs about 2^256 operations and finding a collision costs about 2^128 (birthday bound). No practical attack on full SHA-256 is known.
- **Length extension.** As a Merkle-Damgard hash, SHA-256 is vulnerable to length-extension attacks. Never construct a MAC as `SHA256(key || message)`; use HMAC.
- **Password storage.** SHA-256 is fast by design and therefore unsuitable for password hashing. Use a memory-hard KDF such as Argon2id, scrypt, or bcrypt.
- **Side channels.** This implementation is not constant-time. This is not a concern when hashing public data, but matters if the hash is applied to secrets in a setting where timing is observable.

## Project structure

```text
.
├── Cargo.toml
├── README.md
└── src
    └── main.rs     # SHA-256 implementation and interactive CLI
```

## Roadmap

- [ ] Incremental hashing API (`update` / `finalize`) with O(1) memory
- [ ] Unit tests covering the NIST test vectors, including multi-block and padding-boundary inputs (55, 56, 63, 64 bytes)
- [ ] File hashing from the command line
- [ ] Benchmarks against the `sha2` crate
- [ ] Separation into a library crate (`lib.rs`) and a binary

## References

1. NIST, *FIPS PUB 180-4: Secure Hash Standard (SHS)*, 2015. https://csrc.nist.gov/pubs/fips/180-4/upd1/final
2. D. Eastlake and T. Hansen, *RFC 6234: US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)*, 2011. https://datatracker.ietf.org/doc/html/rfc6234
3. R. Merkle, *A Certified Digital Signature*, CRYPTO 1989.
4. I. Damgard, *A Design Principle for Hash Functions*, CRYPTO 1989.
5. M. Bellare, R. Canetti, H. Krawczyk, *Keying Hash Functions for Message Authentication*, CRYPTO 1996.

## License

Released under the MIT License. See `LICENSE` for details.

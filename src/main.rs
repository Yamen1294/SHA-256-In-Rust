use std::fmt::Write;
use std::io::{self, Write as IoWrite};

// SHA-256 round constants
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// Initial hash values
const H0: [u32; 8] = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
];

#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2)
        ^ x.rotate_right(13)
        ^ x.rotate_right(22)
}

#[inline]
fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6)
        ^ x.rotate_right(11)
        ^ x.rotate_right(25)
}

#[inline]
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7)
        ^ x.rotate_right(18)
        ^ (x >> 3)
}

#[inline]
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17)
        ^ x.rotate_right(19)
        ^ (x >> 10)
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
    
    // PREPROCESSING / PADDING


    let mut message: Vec<u8> = input.to_vec();

    // Append one '1' bit = 0x80
    message.push(0x80);


    // message length ≡ 56 (mod 64)
    while message.len() % 64 != 56 {
        message.push(0);
    }

    // Original length in bits
    let bit_length = (input.len() as u64) * 8;

    // Append 64-bit big-endian length
    message.extend_from_slice(&bit_length.to_be_bytes());


    //  INITIAL HASH STATE


    let mut h = H0;


    //  PROCESS EACH 512-BIT BLOCK


    for chunk in message.chunks_exact(64) {


        // MESSAGE SCHEDULE


        let mut w = [0u32; 64];

        // First 16 words come directly from the block
        for i in 0..16 {
            let j = i * 4;

            w[i] = u32::from_be_bytes([
                chunk[j],
                chunk[j + 1],
                chunk[j + 2],
                chunk[j + 3],
            ]);
        }

        // Expand W[16..63]
        for i in 16..64 {
            w[i] = small_sigma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(small_sigma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }


        // COMPRESSION
    

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {

            let t1 = hh
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);

            let t2 = big_sigma0(a)
                .wrapping_add(maj(a, b, c));

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

   
        // ADD COMPRESSED CHUNK TO CURRENT HASH
        

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    
    // CONVERT 8 x u32 → 32 BYTES
   

    let mut output = [0u8; 32];

    for i in 0..8 {
        output[i * 4..i * 4 + 4]
            .copy_from_slice(&h[i].to_be_bytes());
    }

    output
}

fn to_hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        write!(&mut result, "{:02x}", byte).unwrap();
    }

    result
}

fn main() {
    print!("Enter string to hash: ");
    io::stdout().flush().unwrap(); 

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

  
    let input = input.trim_end_matches(&['\r', '\n'][..]);

    let hash = sha256(input.as_bytes());

    println!("SHA-256: {}", to_hex(&hash));
}
// XEdDSA test-vector oracle.
//
// Emits deterministic vectors that geryon's src/core/ed25519.c is checked
// against.  Two record kinds, blank-line separated, one `key=hexvalue` per
// line:
//
//   sign record:   sk, pk, msg, z, sig
//     geryon must reproduce `sig` byte-exact from gy_xeddsa_sign_z(sk,msg,z)
//     and accept it with gy_xeddsa_verify(sig, pk, msg).
//
//   verify record: pk, msg, sig, valid
//     geryon's gy_xeddsa_verify must accept iff valid == 01.
//
// libsignal (AGPL) runs here as a separate process only; its code is never
// linked into or copied by geryon.  Regenerate with:
//
//   cargo run --release > ../../../tests/vectors/xeddsa_libsignal.vec
//
// and update docs/TEST_ORACLES.md (crate version, command, file hash).

use libsignal_protocol::KeyPair;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

// rand_core 0.9: RngCore has next_u32/next_u64/fill_bytes (fill_bytes is
// infallible; try_fill_bytes and rand::Error were removed).  CryptoRng is a
// marker with RngCore as a supertrait.

const N_SIGN: u64 = 256;
const N_VERIFY: u64 = 64;
const MAX_MSG: usize = 8192;

// Wraps an RNG and records every byte it hands out, so we can recover the
// 64-byte XEdDSA nonce Z that calculate_signature consumed.
struct Recorder<R> {
    inner: R,
    log: Vec<u8>,
}

impl<R: RngCore> RngCore for Recorder<R> {
    fn next_u32(&mut self) -> u32 {
        let v = self.inner.next_u32();
        self.log.extend_from_slice(&v.to_le_bytes());
        v
    }
    fn next_u64(&mut self) -> u64 {
        let v = self.inner.next_u64();
        self.log.extend_from_slice(&v.to_le_bytes());
        v
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
        self.log.extend_from_slice(dest);
    }
}

impl<R: CryptoRng> CryptoRng for Recorder<R> {}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn main() {
    let mut out = String::new();

    // Sign vectors: byte-exact reproduction requires the nonce Z, captured via
    // the recording RNG.  A fresh RNG is used only for signing so the recorded
    // bytes are exactly Z (no key-generation draws mixed in).
    // Only sign-bit-0 keys are emitted: libsignal deviates from the XEdDSA
    // paper for keys whose E = kB has sign bit 1, storing that sign in bit 255
    // of s.  geryon follows the paper (canonical s), so it agrees with
    // libsignal only for sign-bit-0 keys.  That bit is exactly (sig[63] & 0x80),
    // so we regenerate the key until it is clear.  See D-XED-11.
    for i in 0..N_SIGN {
        let msg_len = (i as usize * 37) % (MAX_MSG + 1);
        let mut msg = vec![0u8; msg_len];
        ChaCha20Rng::seed_from_u64(0xd1b5_4a32_0000_0000 ^ i).fill_bytes(&mut msg);

        let mut attempt = 0u64;
        loop {
            let salt = i ^ (attempt << 40);
            let mut keygen = ChaCha20Rng::seed_from_u64(0x9e37_79b9_0000_0000 ^ salt);
            let kp = KeyPair::generate(&mut keygen);
            let mut rec = Recorder {
                inner: ChaCha20Rng::seed_from_u64(0xa076_1d64_0000_0000 ^ salt),
                log: Vec::new(),
            };
            let sig = kp
                .private_key
                .calculate_signature(&msg, &mut rec)
                .expect("calculate_signature");
            assert_eq!(rec.log.len(), 64, "expected a single 64-byte nonce draw");
            if sig[63] & 0x80 != 0 {
                attempt += 1;
                continue; // sign-bit-1 key; try another
            }
            let sk = kp.private_key.serialize();
            let pk_full = kp.public_key.serialize(); // 0x05 || 32-byte u
            let pk = &pk_full[1..];
            out.push_str(&format!("sk={}\n", hex(&sk)));
            out.push_str(&format!("pk={}\n", hex(pk)));
            out.push_str(&format!("msg={}\n", hex(&msg)));
            out.push_str(&format!("z={}\n", hex(&rec.log)));
            out.push_str(&format!("sig={}\n", hex(&sig)));
            out.push('\n');
            break;
        }
    }

    // Verify vectors: half valid, half corrupted.  Same sign-bit-0 filter.
    for i in 0..N_VERIFY {
        let msg = format!("geryon verify case {i}").into_bytes();
        let mut attempt = 0u64;
        loop {
            let salt = i ^ (attempt << 40);
            let mut keygen = ChaCha20Rng::seed_from_u64(0x2545_f491_0000_0000 ^ salt);
            let kp = KeyPair::generate(&mut keygen);
            let mut signer = ChaCha20Rng::seed_from_u64(0x94d0_49bb_0000_0000 ^ salt);
            let mut sig = kp
                .private_key
                .calculate_signature(&msg, &mut signer)
                .expect("calculate_signature")
                .to_vec();
            if sig[63] & 0x80 != 0 {
                attempt += 1;
                continue;
            }
            let valid = i % 2 == 0;
            if !valid {
                // Corrupt the R half so rejection is about validity, not the
                // s canonicality that carries the (already-clear) sign bit.
                sig[i as usize % 32] ^= 0x01;
            }
            let pk_full = kp.public_key.serialize();
            let pk = &pk_full[1..];
            out.push_str(&format!("pk={}\n", hex(pk)));
            out.push_str(&format!("msg={}\n", hex(&msg)));
            out.push_str(&format!("sig={}\n", hex(&sig)));
            out.push_str(&format!("valid={}\n", if valid { "01" } else { "00" }));
            out.push('\n');
            break;
        }
    }

    print!("{out}");
}

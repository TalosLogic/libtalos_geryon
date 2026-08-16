// X3DH DH-stage test-vector oracle.
//
// Emits deterministic vectors that geryon's src/kex/x3dh.c DH stage is checked
// against: for a synthetic handshake, the four X3DH Diffie-Hellman outputs
// (the X3DH specification, section 3) computed with libsignal's own X25519.  geryon must
// reproduce each with its descriptor dh op over the same spec pairing.
//
// Scope note (D-GEN-6): libsignal's public API does NOT expose the assembled
// X3DH master secret (SK) or its HKDF info string - session establishment
// returns an opaque SessionRecord, and `PrivateKey::calculate_agreement` is
// the only prescriptive intermediate it will emit.  So this oracle validates
// the DH stage only; the SK/F/salt/HKDF/info composition is geryon-specific
// and covered by the F-guard KAT and self-vectors in tests/kex/test_x3dh.c.
//
// libsignal (AGPL) runs here as a separate process only; its code is never
// linked into or copied by geryon.  Regenerate with:
//
//   cargo run --release > ../../../tests/vectors/x3dh_libsignal.vec
//
// and update docs/TEST_ORACLES.md (crate version, command, file hash).
//
// Record fields (blank-line separated, one key=hexvalue per line):
//   ik_a_sk, ek_a_sk   - initiator identity / ephemeral private scalars
//   ik_b_pk, spk_b_pk  - responder identity / signed-prekey public u-coords
//   opk_b_pk           - responder one-time-prekey public u-coord (opk==01 only)
//   dh1..dh4           - DH1=(IK_A,SPK_B) DH2=(EK_A,IK_B) DH3=(EK_A,SPK_B)
//                        DH4=(EK_A,OPK_B); dh4 present only when opk==01
//   opk                - 01 if a one-time prekey is used, else 00

use libsignal_protocol::KeyPair;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const N_WITH_OPK: u64 = 16;
const N_NO_OPK: u64 = 8;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn keypair(seed: u64) -> KeyPair {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    KeyPair::generate(&mut rng)
}

// The 32-byte u-coordinate from libsignal's 0x05 || u public serialization.
fn pk_u(kp: &KeyPair) -> Vec<u8> {
    kp.public_key.serialize()[1..].to_vec()
}

fn agree(sk: &KeyPair, pk: &KeyPair) -> Vec<u8> {
    sk.private_key
        .calculate_agreement(&pk.public_key)
        .expect("calculate_agreement")
        .to_vec()
}

fn emit(out: &mut String, i: u64, with_opk: bool) {
    let base = if with_opk {
        0x1000_0000_0000_0000
    } else {
        0x2000_0000_0000_0000
    } ^ i;

    let ik_a = keypair(0x0a01_0000_0000_0000 ^ base);
    let ek_a = keypair(0x0e02_0000_0000_0000 ^ base);
    let ik_b = keypair(0x0b03_0000_0000_0000 ^ base);
    let spk_b = keypair(0x5904_0000_0000_0000 ^ base);
    let opk_b = keypair(0x0c05_0000_0000_0000 ^ base);

    let dh1 = agree(&ik_a, &spk_b); // DH(IK_A, SPK_B)
    let dh2 = agree(&ek_a, &ik_b); //  DH(EK_A, IK_B)
    let dh3 = agree(&ek_a, &spk_b); // DH(EK_A, SPK_B)

    out.push_str(&format!("ik_a_sk={}\n", hex(&ik_a.private_key.serialize())));
    out.push_str(&format!("ek_a_sk={}\n", hex(&ek_a.private_key.serialize())));
    out.push_str(&format!("ik_b_pk={}\n", hex(&pk_u(&ik_b))));
    out.push_str(&format!("spk_b_pk={}\n", hex(&pk_u(&spk_b))));
    out.push_str(&format!("dh1={}\n", hex(&dh1)));
    out.push_str(&format!("dh2={}\n", hex(&dh2)));
    out.push_str(&format!("dh3={}\n", hex(&dh3)));
    if with_opk {
        let dh4 = agree(&ek_a, &opk_b); // DH(EK_A, OPK_B)
        out.push_str(&format!("opk_b_pk={}\n", hex(&pk_u(&opk_b))));
        out.push_str(&format!("dh4={}\n", hex(&dh4)));
        out.push_str("opk=01\n");
    } else {
        out.push_str("opk=00\n");
    }
    out.push('\n');
}

fn main() {
    let mut out = String::new();
    for i in 0..N_WITH_OPK {
        emit(&mut out, i, true);
    }
    for i in 0..N_NO_OPK {
        emit(&mut out, i, false);
    }
    print!("{out}");
}

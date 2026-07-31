//! Generate SM2 certificates for mTLS testing using gm-ca's CaSigner.
//!
//! This example creates:
//! - A self-signed CA certificate
//! - Server certificate signed by CA
//! - Client certificate signed by CA
//!
//! Usage: cargo run --example generate_sm2_certs

use asn1::{ObjectIdentifier, SequenceWriter};
use elliptic_curve::sec1::ToEncodedPoint;
use gm_ca::cert::CaSigner;
use gm_crypto::sm2::Sm2KeyPair;
use std::fs;
use std::path::PathBuf;

// SM2 public key OID: 1.2.156.10197.1.301 = 2A 8C D8 E3 65 6A 01 01
const SM2_PK_OID_BYTES: &[u8] = &[0x2A, 0x8C, 0xD8, 0xE3, 0x65, 0x6A, 0x01, 0x01];
// CN OID: 2.5.4.3 = 55 04 03
const CN_OID_BYTES: &[u8] = &[0x55, 0x04, 0x03];

fn sm2_sig_oid() -> ObjectIdentifier {
    ObjectIdentifier::from_string("1.2.156.10197.1.501").unwrap()
}
fn sm2_pk_oid() -> ObjectIdentifier {
    ObjectIdentifier::from_string("1.2.156.10197.1.301").unwrap()
}
fn cn_oid() -> ObjectIdentifier {
    ObjectIdentifier::from_string("2.5.4.3").unwrap()
}

/// Build the CRI (CertificationRequestInfo) portion of a CSR with asn1.
/// The [0] attributes field uses correct [0] IMPLICIT encoding (A0 00).
fn build_cri_with_attrs(
    subject_cn: &str,
    public_key_bytes: &[u8],
    _sm2_pk_oid: &ObjectIdentifier,
    _cn_oid: &ObjectIdentifier,
) -> Result<Vec<u8>, asn1::WriteError> {
    // Build the SM2 PK OID as raw DER bytes (to ensure correct encoding)
    let sm2_pk_oid_der = {
        let mut v = vec![0x06]; // OID tag
        v.push(SM2_PK_OID_BYTES.len() as u8);
        v.extend_from_slice(SM2_PK_OID_BYTES);
        v
    };

    // Build the CN OID as raw DER bytes
    let cn_oid_der = {
        let mut v = vec![0x06]; // OID tag
        v.push(CN_OID_BYTES.len() as u8);
        v.extend_from_slice(CN_OID_BYTES);
        v
    };

    // Build subject name: SEQUENCE { OID, UTF8String }
    let cn_value = subject_cn.as_bytes();
    let subject_name = {
        let mut v = vec![0x30]; // SEQUENCE
        let inner_len = cn_oid_der.len() + 2 + cn_value.len(); // OID + UTF8 tag+len + value
        v.push(inner_len as u8);
        v.extend_from_slice(&cn_oid_der);
        v.push(0x0C); // UTF8String tag
        v.push(cn_value.len() as u8);
        v.extend_from_slice(cn_value);
        // Wrap in SET
        let set_content = v.clone();
        let mut set = vec![0x31]; // SET
        set.push(set_content.len() as u8);
        set.extend_from_slice(&set_content);
        // Wrap in SEQUENCE
        let mut seq = vec![0x30]; // SEQUENCE
        seq.push(set.len() as u8);
        seq.extend_from_slice(&set);
        seq
    };

    // Build SPKI: SEQUENCE { AlgorithmIdentifier, BitString }
    let spki = {
        // AlgorithmIdentifier: SEQUENCE { OID, NULL }
        let alg_id_content = {
            let mut v = Vec::new();
            v.extend_from_slice(&sm2_pk_oid_der); // OID DER (includes tag and length)
            v.extend_from_slice(&[0x05, 0x00]); // NULL
            v
        };
        let mut alg_id = vec![0x30]; // SEQUENCE tag
        if alg_id_content.len() < 128 {
            alg_id.push(alg_id_content.len() as u8);
        } else {
            alg_id.push(0x82);
            alg_id.push((alg_id_content.len() >> 8) as u8);
            alg_id.push(alg_id_content.len() as u8);
        }
        alg_id.extend_from_slice(&alg_id_content);

        // BitString: 03 41 00 || public_key_bytes
        let bit_string_content_len = 1 + public_key_bytes.len(); // 0x00 prefix + key
        let mut bit_string = vec![0x03]; // BIT STRING tag
        if bit_string_content_len < 128 {
            bit_string.push(bit_string_content_len as u8);
        } else {
            bit_string.push(0x82);
            bit_string.push((bit_string_content_len >> 8) as u8);
            bit_string.push(bit_string_content_len as u8);
        }
        bit_string.push(0x00); // no unused bits
        bit_string.extend_from_slice(public_key_bytes);

        // Wrap in SEQUENCE
        let spki_content_len = alg_id.len() + bit_string.len();
        let mut seq = vec![0x30]; // SEQUENCE tag
        if spki_content_len < 128 {
            seq.push(spki_content_len as u8);
        } else {
            seq.push(0x82);
            seq.push((spki_content_len >> 8) as u8);
            seq.push(spki_content_len as u8);
        }
        seq.extend_from_slice(&alg_id);
        seq.extend_from_slice(&bit_string);
        seq
    };

    // Build CRI: SEQUENCE { version, subject, spki, [0] empty }
    let version = vec![0x02, 0x01, 0x00]; // INTEGER 0
    let attributes = vec![0xA0, 0x00]; // [0] empty

    let cri_content_len = version.len() + subject_name.len() + spki.len() + attributes.len();
    let mut cri = vec![0x30]; // SEQUENCE
    if cri_content_len < 128 {
        cri.push(cri_content_len as u8);
    } else {
        // Use 2-byte length encoding
        cri.push(0x82);
        cri.push((cri_content_len >> 8) as u8);
        cri.push(cri_content_len as u8);
    }
    cri.extend_from_slice(&version);
    cri.extend_from_slice(&subject_name);
    cri.extend_from_slice(&spki);
    cri.extend_from_slice(&attributes);

    Ok(cri)
}

fn build_csr_der_fixed(
    subject_cn: &str,
    public_key_bytes: &[u8],
    signing_key: &Sm2KeyPair,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let sm2_sig_oid = sm2_sig_oid();
    let sm2_pk_oid = sm2_pk_oid();
    let cn_oid = cn_oid();

    // Build CRI (CertificationRequestInfo) with [0] empty attributes
    let cri = build_cri_with_attrs(subject_cn, public_key_bytes, &sm2_pk_oid, &cn_oid)?;

    // Sign CRI with SM2 private key
    let signer = gm_crypto::sm2::Sm2Signer::new(signing_key)?;
    let sig = signer.sign(&cri)?;

    // Build sigAlg: SEQUENCE { OID }
    let sig_alg = asn1::write_single(&SequenceWriter::new(&|w| {
        w.write_element(&sm2_sig_oid)?;
        Ok(())
    }))?;

    // Build sigValue: BIT STRING
    let sig_value = asn1::write_single(&asn1::BitString::new(&sig, 0).unwrap())?;

    // Build full CSR: SEQUENCE { CRI, sigAlg, sigValue }
    // Each component is already DER-encoded; just concatenate and wrap in SEQUENCE
    let inner_len = cri.len() + sig_alg.len() + sig_value.len();
    let mut csr = vec![0x30]; // SEQUENCE tag
    if inner_len < 128 {
        csr.push(inner_len as u8);
    } else if inner_len < 0x10000 {
        csr.push(0x82);
        csr.push((inner_len >> 8) as u8);
        csr.push(inner_len as u8);
    } else {
        csr.push(0x83);
        csr.push((inner_len >> 16) as u8);
        csr.push((inner_len >> 8) as u8);
        csr.push(inner_len as u8);
    }
    csr.extend_from_slice(&cri);
    csr.extend_from_slice(&sig_alg);
    csr.extend_from_slice(&sig_value);

    Ok(csr)
}

fn csr_to_pem_fixed(csr_der: &[u8]) -> String {
    pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", csr_der))
}

/// Build a PKCS#10 CSR DER for SM2 public key (self-signed).
fn build_sm2_csr_der(
    subject_cn: &str,
    public_key_bytes: &[u8],
    signing_key: &Sm2KeyPair,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    build_csr_der_fixed(subject_cn, public_key_bytes, signing_key)
}

fn csr_to_pem(csr_der: &[u8]) -> String {
    csr_to_pem_fixed(csr_der)
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Generating SM2 certificates for mTLS testing...\n");

    // Output directory
    let out_dir = std::env::var("CERT_OUTPUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("certs"));

    fs::create_dir_all(&out_dir)?;

    // 1. Create test CA keypair
    let ca_keypair = Sm2KeyPair::generate()?;
    let _ca_key_pem = ca_keypair.private_key_pem()?;
    #[allow(unused_variables)]
    let ca_signer = CaSigner::new(ca_keypair.duplicate(), "Test GM CA");

    // 2. Generate server keypair + CSR (self-signed so sign_csr validation passes)
    let server_keypair = Sm2KeyPair::generate()?;
    let server_pubkey = server_keypair.public_key().to_encoded_point(false);
    let server_pubkey_bytes = server_pubkey.as_bytes();
    let server_csr_der = build_sm2_csr_der("server.test", server_pubkey_bytes, &server_keypair)?;
    let server_csr_pem = csr_to_pem(&server_csr_der);

    // 3. Generate client keypair + CSR
    let client_keypair = Sm2KeyPair::generate()?;
    let client_pubkey = client_keypair.public_key().to_encoded_point(false);
    let client_pubkey_bytes = client_pubkey.as_bytes();
    let client_csr_der = build_sm2_csr_der("client.test", client_pubkey_bytes, &client_keypair)?;
    let client_csr_pem = csr_to_pem(&client_csr_der);

    // 4. Sign both certs with our test CA
    let server_cert_pem = ca_signer.sign_csr(server_csr_pem.as_bytes(), 365)?;
    let client_cert_pem = ca_signer.sign_csr(client_csr_pem.as_bytes(), 365)?;

    // 5. CA self-signed cert for trust chain
    let ca_pubkey = ca_keypair.public_key().to_encoded_point(false);
    let ca_pubkey_bytes = ca_pubkey.as_bytes();
    let ca_csr_der = build_sm2_csr_der("Test GM CA", ca_pubkey_bytes, &ca_keypair)?;
    let ca_csr_pem = csr_to_pem(&ca_csr_der);
    let ca_cert_pem = ca_signer.sign_csr(ca_csr_pem.as_bytes(), 3650)?;

    // 6. Write to output directory
    let write_str = |name: &str, data: &str| {
        let path = out_dir.join(name);
        fs::write(&path, data).expect("failed to write file");
        println!("  Wrote: {}", path.display());
        path
    };

    println!("\nWriting certificates to {}:", out_dir.display());
    write_str("ca.pem", &ca_cert_pem.0);
    write_str("server.pem", &server_cert_pem.0);
    write_str(
        "server-key.pem",
        &server_keypair
            .private_key_pem()
            .map_err(|e| anyhow::anyhow!("{}", e))?,
    );
    write_str("client.pem", &client_cert_pem.0);
    write_str(
        "client-key.pem",
        &client_keypair
            .private_key_pem()
            .map_err(|e| anyhow::anyhow!("{}", e))?,
    );

    println!("\nCertificate generation complete!");
    println!("\nUsage with KMS server:");
    println!("  TLS_CERT_PATH=certs/server.pem");
    println!("  TLS_KEY_PATH=certs/server-key.pem");
    println!("  TLS_CA_PATH=certs/ca.pem");
    println!("  TLS_REQUIRE_CLIENT_CERT=true");

    Ok(())
}

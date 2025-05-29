use p256::{
    ecdsa::{SigningKey, VerifyingKey, Signature, signature::{Signer, Verifier}},
    FieldBytes,
    SecretKey
};
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Write;
use num_bigint::BigUint;
use hex;
use rand::rngs::OsRng;

// run with cargo run --bin generate_test_data
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_pair = KeyPair::new(Some("345763aa024409b31f932c7098a4e4c4e8519182a8b726aa5b105c47582c2a4c"))?;
    
    // Print the keys
    println!("Private Key (hex): {}", hex::encode(key_pair.get_private_key()));
    println!("Public Key (hex): {}", hex::encode(key_pair.get_public_key()));

    // Create a test message and hash it
    let message = b"Hello world";

    let mut hasher = Sha256::new();
    hasher.update(message);
    let hashed_message = hasher.finalize();

    // Sign the hashed message
    let signature: SignatureComponents = key_pair.sign(message);

    println!("Message hash: {:?}", signature.message_hash);
    
    // Expected signature
    let expected_sig: Vec<u8> = vec![
        134, 81, 58, 11, 66, 31, 17, 150, 155, 146, 88, 208, 25, 225, 157, 226, 
        233, 200, 254, 29, 101, 17, 190, 98, 165, 125, 141, 208, 220, 47, 8, 124, 
        187, 136, 109, 172, 186, 22, 16, 38, 242, 8, 252, 145, 121, 173, 38, 146, 
        146, 220, 115, 134, 43, 110, 5, 104, 31, 218, 17, 160, 97, 88, 50, 73
    ];

    // Compare signatures
    let mut our_sig = Vec::with_capacity(64);
    our_sig.extend_from_slice(&signature.r);
    our_sig.extend_from_slice(&signature.s);
    
    println!("Our signature: {:?}", our_sig);
    println!("Expected signature: {:?}", expected_sig);
    println!("Signatures match: {}", our_sig == expected_sig);

    // Get the public key bytes
    let public_key_bytes = key_pair.get_public_key();

    // Format the data according to Prover.toml format
    let hashed_message_vec: Vec<u8> = hashed_message.to_vec();
    let pub_key_x_vec: Vec<u8> = public_key_bytes[1..33].to_vec();
    let pub_key_y_vec: Vec<u8> = public_key_bytes[33..65].to_vec();
    
    // Normalize signature if needed
    let n = BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
    ]);
    let half_order = &n >> 1;
    
    let s_big = BigUint::from_bytes_be(&signature.s);
    let normalized_s = if s_big > half_order {
        let new_s = &n - &s_big;
        let mut normalized_bytes = vec![0u8; 32];
        let s_bytes = new_s.to_bytes_be();
        normalized_bytes[32 - s_bytes.len()..].copy_from_slice(&s_bytes);
        normalized_bytes
    } else {
        signature.s.clone()
    };

    // Format the data according to Prover.toml format
    let toml_content = format!(
        r#"hashed_message = [
    {}
]
pub_key_x = [
    {}
]
pub_key_y = [
    {}
]
signature = [
    {}
]
"#,
        hashed_message_vec.iter()
            .map(|b| b.to_string())
            .collect::<Vec<String>>()
            .join(",\n    "),
        pub_key_x_vec.iter()
            .map(|b| b.to_string())
            .collect::<Vec<String>>()
            .join(",\n    "),
        pub_key_y_vec.iter()
            .map(|b| b.to_string())
            .collect::<Vec<String>>()
            .join(",\n    "),
        [&signature.r[..], &normalized_s[..]].concat()
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<String>>()
            .join(",\n    ")
    );

    // Write to file
    let mut file = File::create("test_data.toml")?;
    file.write_all(toml_content.as_bytes())?;

    println!("Test data has been written to test_data.toml");
    Ok(())
} 

struct SignatureComponents {
    r: Vec<u8>,
    s: Vec<u8>,
    message_hash: Vec<u8>,
}

struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    pub fn new(secret_key_hex: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
        let signing_key = if let Some(hex_str) = secret_key_hex {
            let private_key_bytes = hex::decode(hex_str)?;
            let field_bytes = FieldBytes::from_slice(&private_key_bytes);
            SigningKey::from_bytes(field_bytes)?
        } else {
            let secret_key = SecretKey::random(&mut OsRng);
            SigningKey::from(secret_key)
        };
        Ok(Self { signing_key })
    }

    pub fn sign(&self, message: &[u8]) -> SignatureComponents {
        println!("Message being signed: {:?}", message);
        let mut hasher = Sha256::new();
        hasher.update(message);
        let sha256_hash = hasher.finalize().to_vec();
        
        let signature: Signature = self.signing_key.sign(message);


        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();
        
        // Print raw signature as 64-byte array
        let mut raw_sig = Vec::with_capacity(64);
        raw_sig.extend_from_slice(&r_bytes);
        raw_sig.extend_from_slice(&s_bytes);
        println!("Raw Signature (64 bytes): {:?}", raw_sig);
        
        // Print DER signature
        let der_sig = signature.to_der().to_bytes();
        println!("DER Signature (bytes): {:?}", der_sig);
        
        let components = SignatureComponents {
            r: r_bytes.to_vec(),
            s: s_bytes.to_vec(),
            message_hash: message.to_vec(),
        };
        
        components
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        // Export the public key in SEC1 encoded format
        self.signing_key.verifying_key()
            .to_encoded_point(false) //this gives us the uncompressed format
            .as_bytes()
            .to_vec()
    }

    pub fn get_private_key(&self) -> Vec<u8> {
        // Export the private key as bytes
        self.signing_key.to_bytes().to_vec()
    }

    // pub fn verify_der(&self, message: &[u8], signature: &[u8]) -> bool {
    //     // Verify using this keypair's public key
    //     verify_signature_der(message, signature, &self.get_public_key())
    // }

    pub fn verify(&self, message: &[u8], r: &[u8], s: &[u8]) -> bool {
        let verifying_key = self.signing_key.verifying_key();
        let r_array: [u8; 32] = r.try_into().unwrap_or_default();
        let s_array: [u8; 32] = s.try_into().unwrap_or_default();
    
    Signature::from_scalars(r_array, s_array)
        .map(|sig| verifying_key.verify(message, &sig).is_ok())
        .unwrap_or(false)
    }
}
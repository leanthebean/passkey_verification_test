use p256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::{Signer, Verifier}};
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Write;

// run with cargo run --bin generate_test_data
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a random keypair
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let verifying_key = VerifyingKey::from(&signing_key);

    // Create a test message and hash it
    let message = b"Hello, World!";
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hashed_message = hasher.finalize();

    // Sign the hashed message
    let signature: Signature = signing_key.sign(&hashed_message);
    
    // Verify the signature
    let is_valid = verifying_key.verify(&hashed_message, &signature).is_ok();
    assert!(is_valid, "Generated signature failed verification!");
    println!("Signature verification successful!");

    // Convert the public key coordinates to bytes
    let public_key_bytes = verifying_key.to_encoded_point(false);
    let public_key_x = public_key_bytes.x().unwrap().as_slice();
    let public_key_y = public_key_bytes.y().unwrap().as_slice();

    // Create TOML content
    let toml_content = format!(
        r#"# Test data for ECDSA Secp256r1 verification
public_key_x = {:#?}
public_key_y = {:#?}
signature = {:#?}
hashed_message = {:#?}
"#,
        public_key_x,
        public_key_y,
        signature.to_bytes(),
        hashed_message.to_vec()
    );

    // Write to file
    let mut file = File::create("test_data.toml")?;
    file.write_all(toml_content.as_bytes())?;

    println!("Test data has been written to test_data.toml");
    Ok(())
} 
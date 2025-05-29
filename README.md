# Passkey Verification Test

This project demonstrates passkey verification using Noir.


## Requirements

- Rust & Cargo
- Noir & Barretenberg (follow these steps: https://noir-lang.org/docs/getting_started/quick_start)

## Workflow

1. **Generate Test Data**
   ```bash
   cargo run --bin generate_test_data
   ```
   This will generate the test data in `test_data.toml`.

2. **Generate Test File**
   The test data is then used to generate the test file in `main.nr`.

3. **Run Tests**
   ```bash
   nargo test
   ```
   This will execute the tests using the generated test file.

4. **Noir Program Compilation and Execution**
   ```bash
   nargo check    # Generates Prover.toml file
   nargo execute  # Compiles and executes the Noir program, generating the witness
   ```

5. **Generate Proof**
   ```bash
   bb prove -b ./target/passkey_verification_test.json -w ./target/passkey_verification_test.gz -o ./target
   ```

6. **Generate Verification Key**
   ```bash
   bb write_vk -b ./target/passkey_verification_test.json -o ./target
   ```

7. **Verify the Proof**
   ```bash
   bb verify -k ./target/vk -p ./target/proof
   ```

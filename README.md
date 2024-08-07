# Crypto Agile Example

This project demonstrates how to integrate AES encryption and RSA digital signatures into a Go program. The example ensures the message is protected and verified, making it suitable for Crypto Agile applications.

## Prerequisites

- Go (version 1.13 or later)

## Setup

1. Clone the repository or download the `main.go` file to your local machine.

2. Navigate to the directory where the `main.go` file is located.
  ```
  cd path/to/your/directory
  ```

3. Set the `AES_KEY` environment variable. This key will be used for AES encryption. Replace `thisis16byteskey` with your desired key.

   - On Linux or macOS:
     ```
     export AES_KEY=thisis16byteskey
     ```

   - On Windows (Command Prompt):
     ```
     set AES_KEY=thisis16byteskey
     ```

   - On Windows (PowerShell):
     ```
     $env:AES_KEY="thisis16byteskey"
     ```

## Running the Program

To run the program, use the `go run` command:

```
go run main.go
```

### Example Commands

#### Linux or macOS:

```
export AES_KEY=thisis16byteskey
go run main.go
```

#### Windows (Command Prompt):

```
set AES_KEY=thisis16byteskey
go run main.go
```

#### Windows (PowerShell):

```
$env:AES_KEY="thisis16byteskey"
go run main.go
```

## Output

If everything is set up correctly, you should see output similar to the following:

```
Original Message: Hello, Crypto Agile!
Encrypted Message: [hex-encoded encrypted message]
SHA-256 Hash: [calculated hash]
RSA Signature: [hex-encoded RSA signature]
Signature Verification: true
```

## Code Explanation

- AES Encryption: The `encryptAES` function encrypts a plaintext message using AES encryption.
- Padding: The `pad` function pads the plaintext to ensure it is a multiple of the AES block size. The `unpad` function removes this padding.
- Hashing: The `calculateHash` function calculates the SHA-256 hash of the input.
- RSA Key Pair: The `generateRSAKeyPair` function generates an RSA key pair.
- RSA Signing: The `signRSA` function signs the hashed message using the RSA private key.
- RSA Verification: The `verifyRSA` function verifies the RSA signature using the RSA public key.

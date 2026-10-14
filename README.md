# RSA Encryption 🔐

A Python implementation of the RSA cryptographic algorithm with OAEP padding and a graphical user interface.

The application allows users to generate RSA key pairs, encrypt messages, decrypt ciphertext, and manage cryptographic keys through a simple graphical interface.

## Features

- **RSA encryption and decryption** — encrypt messages using a public key and decrypt them using the corresponding private key.
- **OAEP padding** — use Optimal Asymmetric Encryption Padding for RSA encryption.
- **RSA key generation** — generate key pairs with configurable key sizes:
  - 1024 bits
  - 2048 bits
  - 3072 bits
- **Graphical user interface** — interact with the application through a GUI built with Python's Tkinter.
- **Key management** — save and load public and private keys.
- **Hexadecimal representation** — display encoded messages and ciphertext in hexadecimal format.
- **UTF-8 support** — encrypt and decrypt text messages encoded as UTF-8.
- **Step-by-step visualization** — inspect the intermediate OAEP-encoded block and the final RSA ciphertext.

## Technologies

- **Python 3**
- **Tkinter** — graphical user interface.
- **RSA** — asymmetric public-key cryptography.
- **OAEP** — padding scheme for RSA encryption.
- **JSON** — key storage.
- **Hexadecimal encoding** — representation of ciphertext and intermediate data.

## Project Structure

RSA/ ├── gui.py # Graphical user interface ├── rsa.py # RSA implementation and cryptographic operations └── README.md # Project documentation


## Requirements

- Python 3
- Tkinter (usually included with standard Python installations)

No additional third-party Python packages are required for the basic application, provided that your Python installation includes Tkinter.

## Installation

Clone the repository:

git clone https://github.com/MXNGM/RSA.git


Navigate to the project directory:

cd RSA


## Usage

Launch the graphical interface:

python gui.py


On some systems, you may need to use:

python3 gui.py


### 1. Generate RSA Keys

1. Select the desired key size.
2. Click **Generate Keys**.
3. The application generates a public and a private key.

The public key can be shared with other users.

**Keep your private key secret.** Anyone with access to it may be able to decrypt messages intended for you.

### 2. Encrypt a Message

1. Generate a key pair or load an existing public key.
2. Enter the message in the encryption panel.
3. Click **Encrypt**.
4. Inspect the OAEP-encoded block and the resulting RSA ciphertext.

The ciphertext is displayed in hexadecimal format.

### 3. Decrypt a Message

1. Provide the private key corresponding to the public key used for encryption.
2. Paste the ciphertext in hexadecimal format into the decryption panel.
3. Click **Decrypt**.
4. The application performs RSA decryption, removes the OAEP padding, and displays the original message.

The ciphertext must correspond to the supplied private key and must contain valid OAEP-encoded data.

### 4. Save and Load Keys

The application supports saving and loading RSA keys.

Keys are stored in JSON files in the `klucze` directory:

klucze/ ├── publiczny.json └── prywatny.json


The public key can be distributed to other users. The private key should be stored securely and never shared.

## How RSA Works

RSA is an asymmetric cryptographic algorithm that uses a pair of mathematically related keys.

- **Public key** — used to encrypt messages.
- **Private key** — used to decrypt messages.

RSA key generation is based on the mathematical properties of large prime numbers.

Encryption and decryption use modular exponentiation:

Encryption: c = m^e mod n Decryption: m = c^d mod n


Where:

- `m` is the encoded message.
- `c` is the ciphertext.
- `e` is the public exponent.
- `d` is the private exponent.
- `n` is the RSA modulus.

Before encryption, OAEP transforms the original message into an encoded block suitable for RSA encryption.

During decryption, the original encoded block is recovered using the private key, and OAEP decoding extracts the original message.

## Security Considerations

This project is intended primarily for educational purposes and experimentation with RSA cryptography.

- Use a 2048-bit or larger RSA key for new applications.
- A 1024-bit RSA key is not considered secure for modern security requirements.
- Keep private keys confidential.
- Never commit private keys or other sensitive cryptographic material to a public repository.
- RSA should not be used to encrypt arbitrarily large messages directly. In practical applications, hybrid encryption is generally preferred.
- Use a well-established cryptographic library for production systems.

Although OAEP improves the security of RSA encryption, the security of the complete implementation also depends on the correctness of the implementation, the randomness used during key generation, and the handling of private keys.

This implementation has not been independently audited. It should not be considered production-ready without further security analysis and testing.

## License

If no license has been specified, all rights remain with the copyright holder by default.

# Quantum-Resistant Encryption System (Ring-LWE)

This project implements a post-quantum key encapsulation mechanism (KEM) based on the Ring Learning With Errors (Ring-LWE) problem. It's designed to be resistant to attacks from both classical and quantum computers.

## Features

- Key generation for Ring-LWE
- Key encapsulation mechanism (KEM)
- Polynomial arithmetic in ring Z_q[x]/(x^n + 1)
- Discrete Gaussian sampling for error terms
- SHA-256 based shared secret derivation

## Requirements

- Python 3.7+
- NumPy
- SymPy

## Installation

1. Install the required packages:
   ```
   pip install numpy sympy
   ```

## Usage

Run the main script to see a demonstration of key generation, encapsulation, and decapsulation:

```
python main.py
```

## Code Structure

- `main.py`: Contains the entire implementation including:
  - Parameter setting
  - Polynomial arithmetic functions
  - Discrete Gaussian sampling
  - Key generation
  - Encapsulation and decapsulation functions

## Security Parameters

- `n = 1024`: Degree of the polynomial ring
- `q = 12289`: Modulus (prime number satisfying q ≡ 1 mod 2n)
- `sigma = 3.2`: Standard deviation for Gaussian error distribution

These parameters are chosen to provide a security level of approximately 128 bits against known quantum attacks.

## Disclaimer

This implementation is for educational purposes only. It has not been audited for use in production environments. Do not use this for actual secure communication without proper review and hardening.



## References

- [The Learning with Errors Problem: Survey and Open Questions](https://arxiv.org/abs/2110.11917)
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
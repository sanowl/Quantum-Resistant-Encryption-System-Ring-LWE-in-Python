import numpy as np
import sympy
import hashlib
import secrets
from sympy.abc import x
from typing import Tuple

# ==========================
# 1. Parameters and Utilities
# ==========================

n = 1024          # Degree of the polynomial ring (power of 2)
q = 12289         # Prime modulus, q ≡ 1 mod 2n
sigma = 3.2       # Standard deviation for Gaussian error distribution
security_level = 128  # Security level in bits

assert sympy.isprime(q), "q must be a prime number."
assert q % (2 * n) == 1, "q must satisfy q ≡ 1 mod 2n for NTT compatibility."

cyclotomic = sympy.Poly(x**n + 1, x, modulus=q)

# ==========================
# 2. Polynomial Arithmetic
# ==========================

def poly_add(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return (a + b) % q

def poly_sub(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return (a - b) % q

def poly_neg(a: np.ndarray) -> np.ndarray:
    return (-a) % q

def poly_mul(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    conv = np.convolve(a, b)
    for i in range(n, len(conv)):
        conv[i - n] = (conv[i - n] - conv[i]) % q
    result = conv[:n] % q
    return result

def poly_inverse(a: np.ndarray) -> np.ndarray:
    poly_a = sympy.Poly(a, x, modulus=q)
    try:
        inv = sympy.invert(poly_a, cyclotomic)
        inv_coeffs = inv.all_coeffs()
        inv_array = np.array(inv_coeffs[::-1], dtype=int) % q
        if len(inv_array) < n:
            inv_array = np.pad(inv_array, (0, n - len(inv_array)), 'constant')
        else:
            inv_array = inv_array[:n]
        return inv_array
    except sympy.polys.polyerrors.NotInvertible:
        raise ValueError("Polynomial is not invertible in R = Z_q[x]/(x^n + 1).")

# ==========================
# 3. Discrete Gaussian Sampling
# ==========================

def discrete_gaussian(sigma: float, size: int) -> np.ndarray:
    samples = []
    while len(samples) < size:
        sample = int(round(secrets.SystemRandom().gauss(0, sigma)))
        samples.append(sample)
    return np.array(samples, dtype=int)

def sample_error(n: int, sigma: float) -> np.ndarray:
    return discrete_gaussian(sigma, n)

# ==========================
# 4. Key Generation
# ==========================

def keygen(n: int, q: int, sigma: float) -> Tuple[Tuple[np.ndarray, np.ndarray], np.ndarray]:
    s = np.array([secrets.choice([-1, 0, 1]) for _ in range(n)], dtype=int)
    a = np.array([secrets.randbelow(q) for _ in range(n)], dtype=int)
    e = sample_error(n, sigma)
    b = poly_add(poly_mul(a, s), e)
    pk = (a, b)
    sk = s
    return pk, sk

# ==========================
# 5. Key Encapsulation Mechanism (KEM)
# ==========================

def hash_shared_secret(v: np.ndarray) -> bytes:
    # Quantize the polynomial to a bitstring
    threshold = q // 2
    bits = ''.join(['1' if coeff > threshold else '0' for coeff in v])
    # Convert bitstring to bytes
    byte_length = (len(bits) + 7) // 8
    quantized = int(bits, 2).to_bytes(byte_length, byteorder='big')
    # Hash the quantized bytes
    digest = hashlib.sha256(quantized).digest()
    return digest

def encapsulate(pk: Tuple[np.ndarray, np.ndarray], sk: np.ndarray, n: int, q: int, sigma: float) -> Tuple[bytes, Tuple[np.ndarray, np.ndarray]]:
    a, b = pk
    r = np.array([secrets.choice([-1, 0, 1]) for _ in range(n)], dtype=int)
    e1 = sample_error(n, sigma)
    e2 = sample_error(n, sigma)
    c1 = poly_add(poly_mul(a, r), e1)
    c2 = poly_add(poly_mul(b, r), e2)
    u = poly_mul(c1, sk)
    v = poly_sub(c2, u)
    shared_secret = hash_shared_secret(v)
    ciphertext = (c1, c2)
    return shared_secret, ciphertext

def decapsulate(ciphertext: Tuple[np.ndarray, np.ndarray], sk: np.ndarray, n: int, q: int, sigma: float) -> bytes:
    c1, c2 = ciphertext
    u = poly_mul(c1, sk)
    v = poly_sub(c2, u)
    shared_secret = hash_shared_secret(v)
    return shared_secret

# ==========================
# 6. Example Usage
# ==========================

def main():
    print("=== Quantum-Resistant Encryption System (Ring-LWE) ===\n")
    
    # Key Generation
    print("Generating key pair...")
    pk, sk = keygen(n, q, sigma)
    print("Public Key (a):", pk[0][:10], "...")  # Display first 10 coefficients
    print("Public Key (b):", pk[1][:10], "...\n")  # Display first 10 coefficients
    
    # Key Encapsulation
    print("Encapsulating shared secret...")
    shared_secret_enc, ciphertext = encapsulate(pk, sk, n, q, sigma)
    c1, c2 = ciphertext
    print("Ciphertext c1 (first 10 coefficients):", c1[:10], "...")
    print("Ciphertext c2 (first 10 coefficients):", c2[:10], "...")
    print("Shared Secret (Encapsulator):", shared_secret_enc.hex(), "\n")
    
    # Key Decapsulation
    print("Decapsulating shared secret...")
    shared_secret_dec = decapsulate(ciphertext, sk, n, q, sigma)
    print("Shared Secret (Decapsulator):", shared_secret_dec.hex(), "\n")
    
    # Verify Shared Secrets
    if shared_secret_enc == shared_secret_dec:
        print("Success: Shared secrets match.")
    else:
        print("Failure: Shared secrets do not match.")

if __name__ == "__main__":
    main()

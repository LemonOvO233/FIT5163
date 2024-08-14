import hashlib
import random
from sympy import isprime, nextprime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

# 获取大质数
def get_large_prime(bits):
    prime = nextprime(2**(bits-1))
    while not isprime(prime):
        prime = nextprime(prime)
    return prime

# Weil pairing 的占位符函数
def weil_pairing(P, Q):
    # 这里需要使用一个真正的库来实现 Weil pairing
    # 这是一个占位符
    return P.public_numbers().x * Q.public_numbers().y

# Setup
def setup(security_parameter):
    p = get_large_prime(security_parameter)
    print(f"Generated prime p: {p}")

    E = ec.SECP256R1()  # 使用标准椭圆曲线
    P = E.curve.generator

    s = random.randint(1, p-1)
    P_pub = s * P

    H = hashlib.sha256
    G = hashlib.sha256

    params = {
        "p": p,
        "E": E,
        "P": P,
        "P_pub": P_pub,
        "H": H,
        "G": G
    }

    master_key = s
    return params, master_key

# Extract
def extract(params, master_key, ID):
    E = params["E"]
    P = params["P"]
    G = params["G"]

    y0 = int(G(ID.encode()).hexdigest(), 16) % params["p"]
    x0 = pow(y0**2 - 1, (2 * params["p"] - 1) // 3, params["p"])
    Q_ID = ec.EllipticCurvePublicNumbers(x0, y0, E).public_key()

    d_ID = master_key * Q_ID.public_numbers().x
    return d_ID

# Encrypt
def encrypt(params, ID, M):
    E = params["E"]
    P = params["P"]
    P_pub = params["P_pub"]
    H = params["H"]
    G = params["G"]

    y0 = int(G(ID.encode()).hexdigest(), 16) % params["p"]
    x0 = pow(y0**2 - 1, (2 * params["p"] - 1) // 3, params["p"])
    Q_ID = ec.EllipticCurvePublicNumbers(x0, y0, E).public_key()

    r = random.randint(1, params["p"] - 1)
    g_ID = weil_pairing(Q_ID, P_pub)  # 需要实现真正的Weil配对

    U = r * P
    V = xor_bytes(M, H(g_ID.to_bytes((g_ID.bit_length() + 7) // 8, 'big')).digest())

    return (U, V)

# Decrypt
def decrypt(params, ID, C, d_ID):
    U, V = C
    H = params["H"]

    g_ID = weil_pairing(d_ID, U)  # 需要实现真正的Weil配对
    M = xor_bytes(V, H(g_ID.to_bytes((g_ID.bit_length() + 7) // 8, 'big')).digest())

    return M

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# 测试算法
security_parameter = 256  # 调整安全参数
params, master_key = setup(security_parameter)
print("Setup complete")

ID = "user@example.com"
private_key = extract(params, master_key, ID)
print("Private key extracted")

message = b"Hello, World!"
ciphertext = encrypt(params, ID, message)
print("Message encrypted")

decrypted_message = decrypt(params, ID, ciphertext, private_key)
print("Message decrypted")

print(f"Original message: {message}")
print(f"Decrypted message: {decrypted_message}")

# 验证加密解密的正确性
assert message == decrypted_message, "Decryption failed!"
print("Encryption and decryption are successful!")

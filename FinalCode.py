import hashlib
import random
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, pair
from charm.core.math.pairing import hashPair as extractor

# Setup
def setup(security_parameter):
    group = PairingGroup('SS512')
    g = group.random(G1)
    s = group.random()
    P_pub = g ** s

    H = hashlib.sha256
    G = hashlib.sha256

    return {
        "group": group,
        "g": g,
        "P_pub": P_pub,
        "H": H,
        "G": G,
    }, s

# Extract
def extract(params, master_key, ID):
    group = params["group"]
    g = params["g"]
    G = params["G"]

    y0 = int(G(ID.encode()).hexdigest(), 16) % group.order()
    Q_ID = g ** y0

    d_ID = Q_ID ** master_key
    return d_ID

# Encrypt
def encrypt(params, ID, M):
    group = params["group"]
    g = params["g"]
    P_pub = params["P_pub"]
    H = params["H"]
    G = params["G"]

    y0 = int(G(ID.encode()).hexdigest(), 16) % group.order()
    Q_ID = g ** y0

    r = group.random()
    g_ID = pair(Q_ID, P_pub) ** r

    U = g ** r
    V = xor_bytes(M, H(extractor(g_ID)).digest())

    return (U, V)

# Decrypt
def decrypt(params, ID, C, d_ID):
    group = params["group"]
    U, V = C
    H = params["H"]

    g_ID = pair(d_ID, U)
    M = xor_bytes(V, H(extractor(g_ID)).digest())

    return M

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# 测试算法
security_parameter = 512  # 调整安全参数
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

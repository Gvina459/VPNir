import secrets

# secp256k1 curve parameters
p = 2**256 - 2**32 - 977 #The prime number used
a = 0 #y^2 = x^3 + ax + b
b = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240 #x,y cords of generator point
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

class ECPoint:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_infinity(self):
        return self.x is None and self.y is None

    @classmethod
    def infinity(cls):
        return cls(None, None)

def mod_inv(x, p):
    return pow(x, p - 2, p)

def ec_add(P, Q, p):
    if P.is_infinity():
        return Q
    if Q.is_infinity():
        return P
    if P == Q:
        return ec_double(P, p)
    if P.x == Q.x and (P.y + Q.y) % p == 0:
        return ECPoint.infinity()

    lambda_add = ((Q.y - P.y) * mod_inv(Q.x - P.x, p)) % p
    x_r = (lambda_add**2 - P.x - Q.x) % p
    y_r = (lambda_add * (P.x - x_r) - P.y) % p
    return ECPoint(x_r, y_r)

def ec_double(P, p):
    if P.is_infinity():
        return P
    lambda_double = ((3 * P.x**2 + a) * mod_inv(2 * P.y, p)) % p
    x_r = (lambda_double**2 - 2 * P.x) % p
    y_r = (lambda_double * (P.x - x_r) - P.y) % p
    return ECPoint(x_r, y_r)

def ec_multiply(P, k, p):
    R = ECPoint.infinity()
    addend = P
    while k:
        if k & 1:
            R = ec_add(R, addend, p)
        addend = ec_double(addend, p)
        k >>= 1
    return R

def generate_keypair():
    G = ECPoint(Gx, Gy)
    private_key = secrets.randbelow(n)
    public_key = ec_multiply(G, private_key, p)
    return private_key, public_key

def compute_shared_secret(private_key, public_key):
    shared_point = ec_multiply(public_key, private_key, p)
    return shared_point.x  # Use x-coordinate as the shared secret

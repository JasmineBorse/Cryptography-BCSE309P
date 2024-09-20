import random


def generateprime():
    first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                         31, 37, 41, 43, 47, 53, 59, 61, 67,
                         71, 73, 79, 83, 89, 97, 101, 103,
                         107, 109, 113, 127, 131, 137, 139,
                         149, 151, 157, 163, 167, 173, 179,
                         181, 191, 193, 197, 199, 211, 223,
                         227, 229, 233, 239, 241, 251, 257,
                         263, 269, 271, 277, 281, 283, 293,
                         307, 311, 313, 317, 331, 337, 347, 349]
     
     
    def nBitRandom(n):
        return random.randrange(2**(n-1)+1, 2**n - 1)
     
     
    def getLowLevelPrime(n):
        while True:
            pc = nBitRandom(n)
            for divisor in first_primes_list:
                if pc % divisor == 0 and divisor**2 <= pc:
                    break
            else:
                return pc
     
     
    def isMillerRabinPassed(mrc):
        maxDivisionsByTwo = 0
        ec = mrc-1
        while ec % 2 == 0:
            ec >>= 1
            maxDivisionsByTwo += 1
        assert(2**maxDivisionsByTwo * ec == mrc-1)
     
        def trialComposite(round_tester):
            if pow(round_tester, ec, mrc) == 1:
                return False
            for i in range(maxDivisionsByTwo):
                if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                    return False
            return True


        numberOfRabinTrials = 20
        for i in range(numberOfRabinTrials):
            round_tester = random.randrange(2, mrc)
            if trialComposite(round_tester):
                return False
        return True
     
    p = 1

    while True:
        n = 1024
        prime_candidate = getLowLevelPrime(n)
        if not isMillerRabinPassed(prime_candidate):
            continue
        else:
            p = prime_candidate
            break
    return p


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi//e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2

        x = x2 - temp1 * x1
        y = d - temp1 * y1

        x2 = x1
        x1 = x
        d = y1
        y1 = y

    if temp_phi == 1:
        return d + phi


def generate_key_pair(p, q):
    n = p * q
    
    phi = (p-1) * (q-1)

    e = 65537

    d = multiplicative_inverse(e, phi)

    return ((e, n), (d, n))


def encrypt(pk, plaintext):
    key, n = pk
    cipher = [pow(ord(char), key, n) for char in plaintext]


    return cipher


def decrypt(pk, ciphertext):
    key, n = pk
    
    aux = [str(pow(char, key, n)) for char in ciphertext]


    plain = [chr(int(char2)) for char2 in aux]
    return ''.join(plain)


p = generateprime()
q = generateprime()

public, private = generate_key_pair(p, q)
print(f"Public key : {public}\n\n")
print(f"Private key : {private}\n\n")


message = input("Message : ")

encrypted_msg = encrypt(public, message)
print("Encrypted message : ", ''.join(map(lambda x: str(x), encrypted_msg)))

print("\n\n\n\n")

decrypted_msg = decrypt(private, encrypted_msg)
print("Decrypted message : ", decrypted_msg)

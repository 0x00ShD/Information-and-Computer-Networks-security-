"""
        RSA Algorithm Implementation In python

Team :-
        Name :-                                ID :-

                Shady Mohmaed                        20200246

                Mohamed Ayman                        20200432

"""
import random


# Square and Multiply Algorithm
def square_and_multiply(base, exponent, modulus):
    result = 1
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent = exponent // 2
    return result


def fermatTest(number):
    return pow(2, number - 1, number) == 1

def isPrime(number):
    if not fermatTest(number):
        return False
    else:
        return True

def GCD(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def eGCD(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = eGCD(b % a, a)
        return g, x - (b // a) * y, y
print("************************************************")
print("*    RSA Algorithm Implementation In python    *")
print("************************************************")
print()

print("Please Enter The 'p' And 'q' Values Below:")
p = int(input("Enter a prime number for p: "))
q = int(input("Enter a prime number for q: "))
print("************************************************")

check_p_isPrime = isPrime(p)
check_q_isPrime = isPrime(q)

while (check_p_isPrime == False) or (check_q_isPrime == False):
    p = int(input("Enter a prime number for p: "))
    q = int(input("Enter a prime number for q: "))
    check_p_isPrime = isPrime(p)
    check_q_isPrime = isPrime(q)

def generateKey():
    

    print()
    print("************************************************")
    print("p value = ", p, "    q value = ", q)
    print("************************************************")
    print()

    n = p * q
    print("RSA Modulus -> n = ", n)
    print()

    r = (p - 1) * (q - 1)
    print("Euler's Toitent -> r = ", r)
    print()

    e = random.randint(1, r)
    g = GCD(e, r)
    while g != 1:
        e = random.randint(1, r)
        g = GCD(e, r)

    print("************************************************")
    print("CoPrime e : ", e)
    print("************************************************")
    print()

    d = eGCD(e, r)[1]
    d = d % r
    if d < 0:
        d += r

    return (e, n), (d, n)

publicKey, privateKey = generateKey()
print("Public Key : ", publicKey)
print("Private Key : ", privateKey)


# Encryption
def encrypt(text, public_key):
    key, n = public_key
    cipher_text = [square_and_multiply(ord(char), key, n) for char in text]
    return cipher_text

def decrypt(cipherText, private_Key):
    try:
        key, n = private_Key
        text = [chr(pow(char, key, n)) for char in cipherText]
        return "".join(text)
    except TypeError as e:
        print(e)

# def crt_decrypt(cipher_text, private_key, p, q):
#     key, n = private_key
#     d_p = private_key[1] % (p - 1)
#     d_q = private_key[1] % (q - 1)
#     q_inv = eGCD(q, p)[1]

#     decrypted_text = []
#     for c in cipher_text:
#         m_p = pow(c, d_p, p)
#         m_q = pow(c, d_q, q)
#         h = (q_inv * (m_p - m_q)) % p
#         m = m_q + h * q
#         decrypted_text.append(m)

#     return ''.join([chr(m % n) for m in decrypted_text])

# Text That You Want To Encrypt/Decrypt
print("************************************************")
message = input("What Would You Like To Encrypt : ")
print("Your message is:", message)
print("************************************************")
print()

encryptedMessage = encrypt(message, publicKey)
print("************************************************")
print("Encrypted Message : ", encryptedMessage)
print("************************************************")
print()

decryptedMessage = decrypt(encryptedMessage, privateKey)
print("************************************************")
print("Decrypted Message : ", decryptedMessage)
print("************************************************")
print()
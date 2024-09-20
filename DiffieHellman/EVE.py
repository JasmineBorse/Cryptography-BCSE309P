import socket
import random

# Define prime number and primitive root
p = 47
g = 5

# Function to perform Diffie-Hellman key exchange
def diffie_hellman(private_key):
    public_key = (g ** private_key) % p
    return public_key

# Function to compute secret key
def compute_secret_key(public_key, private_key):
    return (public_key ** private_key) % p

def main():
    # Create a socket
    eve_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server (Bob)
    eve_socket.connect(('localhost', 12345))
    print("Connected to server (Bob)...")

    # Generate a random private key for Eve
    eve_private_key = random.randint(1, p-1)

    # Perform Diffie-Hellman key exchange with the server (Bob)
    eve_public_key = diffie_hellman(eve_private_key)

    # Receive Bob's public key
    bob_public_key = int(eve_socket.recv(1024).decode())

    # Send Eve's public key to Bob
    eve_socket.send(str(eve_public_key).encode())

    # Compute the shared secret key with Bob
    shared_secret_key_bob = compute_secret_key(bob_public_key, eve_private_key)
    print("Shared secret key computed on Eve's side with Bob:", shared_secret_key_bob)

    # Close the connection with Bob
    eve_socket.close()

    # Connect to the client (Alice)
    eve_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    eve_socket.connect(('localhost', 12346))
    print("Connected to client (Alice)...")

    # Perform Diffie-Hellman key exchange with the client (Alice)
    eve_public_key = diffie_hellman(eve_private_key)

    # Receive Alice's public key
    alice_public_key = int(eve_socket.recv(1024).decode())

    # Send Eve's public key to Alice
    eve_socket.send(str(eve_public_key).encode())

    # Compute the shared secret key with Alice
    shared_secret_key_alice = compute_secret_key(alice_public_key, eve_private_key)
    print("Shared secret key computed on Eve's side with Alice:", shared_secret_key_alice)

    # Close the connection with Alice
    eve_socket.close()

if __name__ == "__main__":
    main()

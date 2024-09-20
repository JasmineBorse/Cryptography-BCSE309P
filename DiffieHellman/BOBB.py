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
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to localhost and port 12345
    server_socket.bind(('localhost', 12345))

    # Listen for incoming connections
    server_socket.listen(1)
    print("Server is listening for incoming connections...")

    # Accept a connection
    connection, address = server_socket.accept()
    print(f"Connected to client at {address}")

    # Generate a random private key for Bob
    bob_private_key = random.randint(1, p-1)

    # Perform Diffie-Hellman key exchange with the client (Alice)
    bob_public_key = diffie_hellman(bob_private_key)

    # Send Bob's public key to the client (Alice)
    connection.send(str(bob_public_key).encode())

    # Receive Alice's public key
    alice_public_key = int(connection.recv(1024).decode())

    # Compute the shared secret key with Alice
    shared_secret_key_alice = compute_secret_key(alice_public_key, bob_private_key)
    print("Shared secret key computed on Bob's side with Alice:", shared_secret_key_alice)

    # Close the connection
    connection.close()
    server_socket.close()

if __name__ == "__main__":
    main()

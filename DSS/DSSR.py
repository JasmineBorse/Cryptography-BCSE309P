import socket
import hashlib
import hmac

# Function to generate HMAC (Hash-based Message Authentication Code) of the message using a symmetric key
def generate_hmac(message, key):
    return hmac.new(key, message, hashlib.sha256).digest()

# Receiver code
def receiver():
    # Create a socket object
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Define the port on which you want to listen
    port = 12345

    # Bind to the port
    receiver_socket.bind(('127.0.0.1', port))

    # Listen for incoming connections
    receiver_socket.listen(1)

    # Accept a connection
    connection, address = receiver_socket.accept()

    # Receive data from sender
    data = connection.recv(4096)
    message, hmac_value = data.split(b'\n')

    # Shared secret key
    key = b'secret_key'

    # Verify the signature by recomputing the HMAC and comparing it with the received HMAC
    computed_hmac = generate_hmac(message, key)
    if hmac.compare_digest(computed_hmac, hmac_value):
        print("Signature verified. Message from sender:", message.decode())
    else:
        print("Signature verification failed. Message could be tampered.")

    # Close the connection
    connection.close()
    receiver_socket.close()

# Main function to start receiver
def main():
    receiver()

if __name__ == "__main__":
    main()

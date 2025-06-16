import socket
import sys

# Configurations
# Match Host and Port with server
HOST = '127.0.0.1'  # Server IP
PORT = 65432        # Server Port

# Client setup
def start_client():
    try:
        # Create a TCP/IP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            # Connect to the server
            client_socket.connect((HOST, PORT))
            print(f"Connected to server at {HOST}:{PORT}")

            # Send a message to the server
            message_to_send = "Hello, Server!"
            client_socket.sendall(message_to_send.encode('utf-8'))
            print(f"Sent to server: '{message_to_send}'")

            # Receive a response from the server
            data = client_socket.recv(1024)
            if data: # Check if data is not empty
                    received_message = data.decode('utf-8')
                    print(f"Received from server: '{received_message}'")
            else:
                    print("Server disconnected without sending a response.")
            

    except ConnectionRefusedError:
        print(f"Connection to {HOST}:{PORT} refused. Is the server running?")
        sys.exit(1)
    except OSError as e:
        print(f"Socket error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        print("Client shutting down.")

# Execute the client function if this script is run directly
if __name__ == "__main__":
    start_client()
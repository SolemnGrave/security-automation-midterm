import socket
import sys

#Configurations
#Define server IP
#Local IP '127.0.0.1'
HOST = '127.0.0.1'
#Define server port
PORT = 65432

#Server setup
def start_server():
    try:
        # Create a TCP/IP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            # Bind the socket to the address and port
            server_socket.bind((HOST, PORT))
            # Listen for incoming connections
            server_socket.listen(5)
            print(f"Server listening on {HOST}:{PORT}")
            # Accept connections in a loop
            while True:
                print("Waiting for a connection...")
                # Wait for a connection
                conn, addr = server_socket.accept()
                # Handle the connection for automated closure
                with conn:
                    print(f"Connected by {addr[0]}:{addr[1]}")
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            print(f"Client {addr[0]}:{addr[1]} disconnected.")
                            break
                        received_message = data.decode('utf-8')
                        print(f"Received from {addr[0]}:{addr[1]}: '{received_message}'")
                        # Echo the received message back to the client
                        #Respond to the client
                        response_message = f"Server received: {received_message}"
                        conn.sendall(response_message.encode('utf-8'))
                        print(f"Sent to {addr[0]}:{addr[1]}: '{response_message}'")
                        #'with conn:' ensures the connection is closed automatically
                        # 'while True:' allows continuous communication until the client disconnects
    except OSError as e:
        print(f"Error starting server: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        print("Server shutdown initiated.")
    
# Execute the server function if this script is run directly
if __name__ == "__main__":
    start_server()
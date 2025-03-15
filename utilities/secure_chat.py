import socket
import ssl

def secure_chat():
    host = 'localhost'
    port = 12345
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="path/to/certfile", keyfile="path/to/keyfile")

    with socket.create_server((host, port)) as server_socket:
        with context.wrap_socket(server_socket, server_side=True) as secure_socket:
            print("Secure chat server started")
            conn, addr = secure_socket.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    print(f"Received message: {data.decode()}")
                    conn.sendall(data)
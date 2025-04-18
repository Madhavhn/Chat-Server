import socket
import threading
import ssl

HOST = '192.168.43.188'
PORT = 9050

user_credentials = {
    "user1": "password1",
    "user2": "password2",
    "user3": "password3",
    "server": "password",
}

active_users = {}

def listen_for_messages(client_socket, username):
    while True:
        try:
            message = client_socket.recv(2048).decode('utf-8')
            if message:
                if message == "!disconnect":
                    client_socket.sendall("You have been disconnected.".encode('utf-8'))
                    client_socket.close()
                    del active_users[username]
                    print(f"{username} has been disconnected.")
                    break
                elif ":" in message:
                    recipient, message_content = message.split(":", 1)
                    if recipient == "everyone":
                        for client in active_users.values():
                            if client != client_socket:
                                client.sendall(f"[{username}]: {message_content}".encode('utf-8'))
                    elif recipient in active_users:
                        recipient_socket = active_users[recipient]
                        recipient_socket.sendall(f"[{username}]: {message_content}".encode('utf-8'))
                    else:
                        client_socket.sendall("Recipient not found.".encode('utf-8'))
                else:
                    print(f"[{username}]: {message}")
                    for client in active_users.values():
                        if client != client_socket:
                            client.sendall(f"[{username}]: {message}".encode('utf-8'))
        except ConnectionResetError:
            del active_users[username]
            print(f"{username} has been disconnected.")
            break

def handle_client(client_socket):
    username = client_socket.recv(2048).decode('utf-8')
    if username in user_credentials:
        if username in active_users:
            client_socket.sendall("User is already connected. Please disconnect first.".encode('utf-8'))
            client_socket.close()
        else:
            client_socket.sendall("Username recognized. Please enter your password:".encode('utf-8'))
            password = client_socket.recv(2048).decode('utf-8')
            if password == user_credentials[username]:
                client_socket.sendall("Authentication successful. You have joined the chat room.".encode('utf-8'))
                active_users[username] = client_socket  # Add user to active users
                threading.Thread(target=listen_for_messages, args=(client_socket, username)).start()
                print(f"{username} has joined the chat room.")
            else:
                client_socket.sendall("Invalid password. Connection closed.".encode('utf-8'))
                client_socket.close()
    else:
        client_socket.sendall("Username not recognized. Connection closed.".encode('utf-8'))
        client_socket.close()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"Server is listening on {HOST}:{PORT}")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    with context.wrap_socket(server_socket, server_side=True) as secure_socket:
        try:
            while True:
                client_socket, address = secure_socket.accept()
                threading.Thread(target=handle_client, args=(client_socket,)).start()
        except KeyboardInterrupt:
            print("Server shutting down...")
            secure_socket.close()

if __name__ == '__main__':
    main()

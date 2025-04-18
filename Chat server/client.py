import socket
import threading
import ssl
from plyer import notification
import pwinput

HOST = '192.168.43.188'
PORT = 9050

def receive_messages(client_socket):
    while True:
        message = client_socket.recv(2048).decode('utf-8')
        if not message:
            print("Disconnected from server.")
            break
        print(message)
        notification.notify(
            title='New Message',
            message=message,
            app_name='ChatApp',
            timeout=5
        )

def main():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    client_socket = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=HOST)
    client_socket.connect((HOST, PORT))

    username = input("Enter your username: ").strip()
    client_socket.sendall(username.encode('utf-8'))

    response = client_socket.recv(2048).decode('utf-8')
    print(response)

    if "recognized" in response:
        password = pwinput.pwinput(prompt="Enter your password: ",mask='*').strip()
        client_socket.sendall(password.encode('utf-8'))

        authentication_response = client_socket.recv(2048).decode('utf-8')
        print(authentication_response)

        if "successful" in authentication_response:
            threading.Thread(target=receive_messages, args=(client_socket,)).start()

            print("You have joined the chat room. Type !disconnect to leave.")
            while True:
                recipient = input("Enter the recipient's username (or type 'everyone' to send to all):\n").strip()
                message = input("Enter your message: ").strip()
                if recipient.lower() == "everyone":
                    recipient = "everyone"
                client_socket.sendall(f"{recipient}:{message}".encode('utf-8'))

                if message == "!disconnect":
                    client_socket.sendall("!disconnect".encode('utf-8'))
                    break
        else:
            print("Authentication failed. Connection closed.")
            client_socket.close()
            return
    else:
        print("Username not recognized. Connection closed.")
        client_socket.close()
        return

if __name__ == '__main__':
    main()

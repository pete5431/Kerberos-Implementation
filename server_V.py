import socket
import base64
import time
from security_info import SecurityInfo

def start_server(info):
    """
    The start_server() function takes in an ServerInfo object that contains the HOST, PORT, and KEY.
        -It will establish a connection on the HOST and PORT and listen for connections.
        -Once connected it will listen and send messages in a loop.
        -Ctrl-C to exit or press enter when typing message to exit.
        -The message exchange will be one by one.
        -Outgoing messages are encrypted and incoming messages are decrypted.
        -The client will send the first message while the server waits.
        -Then the server sends its message while the client waits and so on.
        -The key, ciphertext, and plaintext will be printed upon receiving a message from client.
    """
    # Create INET socket. With will automatically close server socket at the end of code block.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # To avoid the error 'Address already in use'.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind socket to the host and port.
        server_socket.bind((info.HOST, info.PORT))
        print("Waiting for client to connect...")
        # Listen for incoming connections.
        server_socket.listen()
        # Accept connection from client.
        client_connect, client_addr = server_socket.accept()
        # Client socket will automatically close after end of with block.
        with client_connect:
            print('Client has connected. Address: ', client_addr)

            print('Checking ticket...')
            service_request = client_connect.recv(1024).decode('UTF-8')
            if service_request == '':
                print("Invalid Ticket. Closing Connection.")
                client_connect.close()

            if validate_ticket_v(info, service_request, client_addr):
                print("Ticket_V: " + info.split_message(service_request)[0])
                print("Ticket_V is valid.")
                mutual_auth = generate_mutual_auth(info, service_request)
                client_connect.sendall(mutual_auth)
            else:
                print("Ticket_V not valid.")
                client_connect.close()

            info.read_des_key("keys/key_des.txt")

            while True:
                print("Waiting for client message...")
                # Will read up to 1024 bytes.
                incoming_message = client_connect.recv(1024)
                # Press enter to close connection.
                if incoming_message == b'':
                    break
                plain_text = info.decrypt_message(incoming_message)

                print("**********************************************************")
                # The returned plaintext string.
                print('Received Plaintext:', plain_text)
                # base64 encoding is used to make ciphertext look more legible.
                print('Received Ciphertext:', incoming_message.decode('UTF-8'))
                print("**********************************************************")

                outgoing_message = input(str(">>"))
                if outgoing_message == '':
                    break
                # Encrypt outgoing message.
                encrypted_outgoing_message = info.encrypt_message(outgoing_message)
                # Sendall will keeping calling send until the entire buffer is sent.
                client_connect.sendall(encrypted_outgoing_message)

                print("**********************************************************")
                print('DES Key:', info.DESKEY.decode('UTF-8'))
                print("Sent Plaintext:", outgoing_message)
                print("Sent Ciphertext:", base64.b64encode(encrypted_outgoing_message).decode('UTF-8'))
                print("**********************************************************")

        print("Connection with client ended.")

def validate_ticket_v(info, service_request, client_addr):
    request_parts = info.split_message(service_request)
    info.read_des_key("keys/key_v.txt")
    ticket_v = info.split_message(info.decrypt_message(request_parts[0]))
    info.set_des_key(bytes(ticket_v[0], 'UTF-8'))
    authenticator = info.split_message(info.decrypt_message(request_parts[1]))
    client_addr = client_addr[0] + ":" + str(client_addr[1])
    if authenticator[0] == info.ID_C and authenticator[1] == client_addr:
        if int(time.time()) - int(ticket_v[4]) < int(ticket_v[5]):
            return True
    return False

def generate_mutual_auth(info, service_request):
    request_parts = info.split_message(service_request)
    info.read_des_key("keys/key_v.txt")
    ticket_v = info.split_message(info.decrypt_message(request_parts[0]))
    info.set_des_key(bytes(ticket_v[0], 'UTF-8'))
    authenticator = info.split_message(info.decrypt_message(request_parts[1]))
    message_contents = str(int(authenticator[2]) + 1)
    return info.encrypt_message(message_contents)

if __name__ == '__main__':
    # Creates the ServerInfo object. A host, port, and key can be passed otherwise it will use the defaults.
    info = SecurityInfo()
    # Start the server with using the info.
    start_server(info)

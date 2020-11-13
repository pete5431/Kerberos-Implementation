import socket
import base64
import time
from security_info import SecurityInfo

def connect_to_server(info):
    """
    Connects to the server using the HOST and PORT from the ServerInfo object.
        -Will be allowed to send the first message.
        -Ctrl-C to exit or press enter will typing message to exit.
    """

    contents = connect_to_AS_TGS(info)

    # With will automatically close the client_socket at the end of the code block.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # Connect to the server using the server host and port.
        client_socket.connect((info.HOST, info.PORT))

        auth_v = generate_auth_v(info, contents[1], contents[0], client_socket.getsockname())
        service_request = generate_service_request(info, contents[0], auth_v, contents[1])

        # Send the service ticket.
        client_socket.sendall(bytes(service_request, 'UTF-8'))

        mutual_auth = client_socket.recv(1024)

        if validate_mutual_auth(info, mutual_auth, service_request):
            print("Mutual Authentication Success.")
        else:
            print("Mutual Authentication Failed.")

        print("Press Enter without typing anything else to close connection.")

        info.read_des_key("keys/key_des.txt")

        while True:
            outgoing_message = input(str(">>"))
            # Press enter to close connection.
            if outgoing_message == '':
                break
            # Concatenate the hmac onto the message and pad it, and encrypt using DES.
            encrypted_outgoing_message = info.encrypt_message(outgoing_message)
            # sendall will keeping calling send until the entire buffer is sent.
            client_socket.sendall(encrypted_outgoing_message)

            print("**********************************************************")
            print('DES Key:', info.DESKEY.decode('UTF-8'))
            print("Sent Plaintext:", outgoing_message)
            print("Sent Ciphertext:", encrypted_outgoing_message.decode('UTF-8'))
            print("**********************************************************")

            print("Waiting for server message...")
            # Will read up to 1024 bytes.
            incoming_message = client_socket.recv(1024)
            if incoming_message == b'':
                break
            plain_text = info.decrypt_message(incoming_message)

            print("**********************************************************")
            # The returned plaintext string.
            print('Received Plaintext:', plain_text)
            # base64 encoding is used to make ciphertext look more legible.
            print('Received Ciphertext:', incoming_message.decode('UTF-8'))
            print("**********************************************************")

    print("Connection has been closed.")

def connect_to_AS_TGS(info):
    """
    Connect to the KDC server (AS and TGS server).
        -Returns the service granting ticket (ticket_v) upon completion if everything goes well.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # Connect to AS/TGS server.
        client_socket.connect((info.HOST, info.PORT_K))
        # Send initial client request.
        client_request = info.ID_C + info.ID_TGS + str(int(time.time()))
        client_socket.sendall(bytes(client_request, 'UTF-8'))

        # Receive the encrypted message from AS.
        message_as = client_socket.recv(1024).decode('UTF-8')

        ticket_tgs = get_ticket_tgs(info, message_as)
        c_tgs_session_key = get_c_tgs_session_key(info, message_as)
        auth_tgs = generate_auth_tgs(info, c_tgs_session_key, client_socket.getsockname())

        info.read_des_key("keys/key_c.txt")
        print("Received PlainText: ", end='')
        print(bytes(info.decrypt_message(message_as), 'UTF-8'))
        print("Received Ticket_TGS: " + ticket_tgs)

        outgoing_message = generate_ticket_v_request(info, message_as, auth_tgs)
        client_socket.sendall(bytes(outgoing_message, 'UTF-8'))

        message_v = client_socket.recv(1024).decode('UTF-8')
        if message_v == b'':
            print("Ticket was not valid.")
            return message_v

        ticket_v = get_ticket_v(info, message_v, c_tgs_session_key)

        info.set_des_key(bytes(c_tgs_session_key, 'UTF-8'))
        print("Received PlainText: ", end='')
        print(bytes(info.decrypt_message(message_v), 'UTF-8'))
        print("Received Ticket_V: " + ticket_v)

    return (message_v, c_tgs_session_key)

def get_c_tgs_session_key(info, message_as):
    info.read_des_key("keys/key_c.txt")
    c_tgs_session_key = info.split_message(info.decrypt_message(message_as))[0]
    return c_tgs_session_key

def get_ticket_tgs(info, message_as):
    info.read_des_key("keys/key_c.txt")
    ticket_tgs = info.split_message(info.decrypt_message(message_as))[4]
    return ticket_tgs

def get_ticket_v(info, message_v, c_tgs_session_key):
    info.set_des_key(bytes(c_tgs_session_key, 'UTF-8'))
    ticket_v = info.split_message(info.decrypt_message(message_v))[3]
    return ticket_v

def validate_mutual_auth(info, mutual_auth, service_request):
    request_parts = info.split_message(service_request)
    info.read_des_key('keys/key_v.txt')
    ticket_v = info.split_message(info.decrypt_message(request_parts[0]))
    info.set_des_key(bytes(ticket_v[0], 'UTF-8'))
    authenticator = info.split_message(info.decrypt_message(request_parts[1]))
    if int(info.decrypt_message(mutual_auth)) == int(authenticator[2]) + 1:
        return True
    return False

def generate_auth_tgs(info, c_tgs_session_key, client_addr):
    """
    Generates the authenticator for tgs ticket.
    """
    info.set_des_key(bytes(c_tgs_session_key, 'UTF-8'))
    AD_C = info.prepend_length(client_addr[0] + ":" + str(client_addr[1]))
    ID_C = info.prepend_length(info.ID_C)
    timestamp = info.prepend_length(str(int(time.time())))
    authenticator = info.encrypt_message(ID_C + AD_C + timestamp).decode('UTF-8')
    return authenticator

def generate_auth_v(info, c_tgs_session_key, message_v, client_addr):
    """
    Generates the authenticator for service ticket.
    """
    info.set_des_key(bytes(c_tgs_session_key, 'UTF-8'))
    c_v_session_key = info.split_message(info.decrypt_message(message_v))[0]
    info.set_des_key(bytes(c_v_session_key, 'UTF-8'))
    AD_C = info.prepend_length(client_addr[0] + ":" + str(client_addr[1]))
    ID_C = info.prepend_length(info.ID_C)
    timestamp = info.prepend_length(str(int(time.time())))
    authenticator = info.encrypt_message(ID_C + AD_C + timestamp).decode('UTF-8')
    return authenticator

def generate_ticket_v_request(info, message_as, authenticator):
    ID_V = info.prepend_length(info.ID_V)
    info.read_des_key("keys/key_c.txt")
    ticket_tgs = info.split_message(info.decrypt_message(message_as))[4]
    return ID_V + info.prepend_length(ticket_tgs) + info.prepend_length(authenticator)

def generate_service_request(info, message_v, authenticator, c_tgs_session_key):
    info.set_des_key(bytes(c_tgs_session_key, 'UTF-8'))
    ticket_v = info.split_message(info.decrypt_message(message_v))[3]
    return info.prepend_length(ticket_v) + info.prepend_length(authenticator)

if __name__ == '__main__':
    # Creates the ServerInfo object. A host, port, and key can be passed otherwise it will use the defaults.
    info = SecurityInfo()
    # Connect to server.
    connect_to_server(info)

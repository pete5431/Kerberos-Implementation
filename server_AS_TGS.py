import socket
import base64
import time
from security_info import SecurityInfo

def start_server(info):
    # Create INET socket. With will automatically close server socket at the end of code block.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # To avoid the error 'Address already in use'.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind socket to the host and port.
        server_socket.bind((info.HOST, info.PORT_K))
        # Listen for incoming connections.
        while True:
            print("Waiting for client to connect...")
            server_socket.listen()
            # Accept connection from client.
            client_connect, client_addr = server_socket.accept()
            with client_connect:
                print('Client has connected. Address: ', client_addr)
                incoming_message = client_connect.recv(1024)
                print("Client Authentication Request: " + incoming_message.decode('UTF-8'))

                message_as = generate_message_as(info, client_addr)
                client_connect.sendall(message_as)

                ticket_v_request = client_connect.recv(1024).decode('UTF-8')
                ticket_tgs = get_ticket_tgs(info, ticket_v_request)
                print("Received Ticket V Request: " + ticket_v_request)
                if validate_ticket_tgs(info, ticket_v_request, client_addr):
                    print("TGS Ticket valid.")
                    message_tgs = generate_message_tgs(info, ticket_tgs, client_addr)
                    client_connect.sendall(message_tgs)
                else:
                    print("TGS Ticket not valid.")
                    client_connect.sendall(b'')
            break

def generate_message_as(info, client_addr):
    """
    Generates the message sent by AS to C.
    """
    c_tgs_session_key = info.prepend_length(info.generate__des_key())
    AD_C = info.prepend_length(client_addr[0] + ":" + str(client_addr[1]))
    ID_C = info.prepend_length(info.ID_C)
    ID_TGS = info.prepend_length(info.ID_TGS)
    Lifetime2 = info.prepend_length(info.Lifetime2)
    timestamp = info.prepend_length(str(int(time.time())))
    ticket_contents = c_tgs_session_key + ID_C + AD_C + ID_TGS + timestamp + Lifetime2
    info.read_des_key("keys/key_tgs.txt")
    ticket_tgs = info.prepend_length(info.encrypt_message(ticket_contents).decode('UTF-8'))
    info.read_des_key("keys/key_c.txt")
    message_contents = c_tgs_session_key + ID_TGS + timestamp + Lifetime2 + ticket_tgs
    message_as = info.encrypt_message(message_contents)
    return message_as

def get_ticket_tgs(info, ticket_v_request):
    ticket_v_request = info.split_message(ticket_v_request)
    info.read_des_key("keys/key_tgs.txt")
    ticket_tgs = info.split_message(info.decrypt_message(ticket_v_request[1]))
    return ticket_tgs

def validate_ticket_tgs(info, ticket_v_request, client_addr):
    request_parts = info.split_message(ticket_v_request)
    ID_V = request_parts[0]
    if ID_V == info.ID_V:
        ticket_tgs = get_ticket_tgs(info, ticket_v_request)
        info.set_des_key(bytes(ticket_tgs[0], 'UTF-8'))
        authenticator = info.split_message(info.decrypt_message(request_parts[2]))
        client_addr = client_addr[0] + ":" + str(client_addr[1])
        if authenticator[0] == info.ID_C and authenticator[1] == client_addr:
            if int(time.time()) - int(ticket_tgs[4]) < int(ticket_tgs[5]):
                return True
    return False

def generate_message_tgs(info, ticket_tgs, client_addr):
    """
    Generates the message sent by TGS to C.
    """
    c_v_session_key = info.prepend_length(info.generate__des_key())
    AD_C = info.prepend_length(client_addr[0] + ":" + str(client_addr[1]))
    ID_C = info.prepend_length(info.ID_C)
    ID_V = info.prepend_length(info.ID_V)
    Lifetime4 = info.prepend_length(info.Lifetime4)
    timestamp = info.prepend_length(str(int(time.time())))
    ticket_contents = c_v_session_key + ID_C + AD_C + ID_V + timestamp + Lifetime4
    info.read_des_key("keys/key_v.txt")
    ticket_v = info.prepend_length(info.encrypt_message(ticket_contents).decode('UTF-8'))
    info.set_des_key(bytes(ticket_tgs[0], 'UTF-8'))
    message_contents = c_v_session_key + ID_V + timestamp + ticket_v
    message_as = info.encrypt_message(message_contents)
    return message_as

if __name__ == '__main__':
    # Creates the ServerInfo object. A host, port, and key can be passed otherwise it will use the defaults.
    info = SecurityInfo()
    # Start the server with using the info.
    start_server(info)

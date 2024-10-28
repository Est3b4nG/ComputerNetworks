from socket import *
import sys
import time
import threading
from threading import Thread

#Server would be running on the same host as Client
if len(sys.argv) != 2:
    print("\n===== Error usage, python3 client.py SERVER_IP SERVER_PORT ======\n")
    exit(0)
serverHost = "127.0.0.1"
serverPort = int(sys.argv[1])
serverAddress = (serverHost, serverPort)

# define a socket for the client side, it would be used to communicate with the server
clientSocket = socket(AF_INET, SOCK_DGRAM)

authenticated = False
heartbeat_running = False

# Function to send heartbeat messages every 2 seconds
def send_heartbeat():
    global heartbeat_running
    while heartbeat_running:
        heartbeat_message = "heartbeat"
        clientSocket.sendto(heartbeat_message.encode(), serverAddress)
        #print("[send] Heartbeat sent")
        time.sleep(2)  # Send heartbeat every 2 seconds

#Function for the thread that will download in the requesting peer
def download_file(peer_ip, peer_port, filename):
    try:
        # Establish TCP connection to peer
        with socket(AF_INET, SOCK_STREAM) as peerSocket:
            peerSocket.connect((peer_ip, peer_port))
            peerSocket.sendall(f"download {filename}".encode())
            
            # Receive the file data and copy it to the existing directory
            with open(filename, "wb") as file:
                while True:
                    data = peerSocket.recv(1024)
                    if not data:   #Waiting for the data
                        break
                    file.write(data)
            print(f"\n[download info] Downloaded {filename} successfully\n")
    except Exception as e:
        print(f"\n[download info] Failed to download {filename}: {e}\n")

#Function for the thread that will upload of the requested peer
def start_file_upload():
    # Create a TCP socket for the client to listen for incoming file download requests
    uploadingSocket = socket(AF_INET, SOCK_STREAM)
    uploadingSocket.bind(('', 0))  # Bind to any available port
    upload_port = uploadingSocket.getsockname()[1]  # Get the port number assigned
    uploadingSocket.listen(5)

    # Inform the main server of the new upload port 
    TCP_port_info = f"{username} upload port will be {upload_port}"
    print(f"\n[send] {TCP_port_info}\n")
    clientSocket.sendto(TCP_port_info.encode(), serverAddress)

    while True:
        # Accept incoming download requests
        peerSockt, peerAddress = uploadingSocket.accept()
        print(f"\n[upload info] Connected to downloading peer {peerAddress}\n")

        # Start a new thread to handle the file upload
        Thread(target=send_file_data, args=(peerSockt,)).start()


# Function to handle sending file data
def send_file_data(peerSockt):
    try:
        # Expect a request with the filename to be downloaded
        request = peerSockt.recv(1024).decode()
        if request.startswith("download"):
            _, filename = request.split()

            # Open the requested file and send its data
            with open(filename, "rb") as file:
                while (chunk := file.read(1024)):   #In case it is a big file, we need to send it by parts
                    peerSockt.sendall(chunk)
            print(f"\n[upload info] File {filename} sent successfully.\n")
    except Exception as e:
        print(f"\n[upload info] Error sending file: {e}\n")
    finally:
        peerSockt.close()


    
while not authenticated:
    print("Username and password are required for further actions")
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    if username == "":
        username = "<Empty>"
    if password == "":
        password = "<Empty>"
    # Send the authentication request (formatted message)
    message = f' login {username} {password}'
    print(f"[send] login {username} {password}")
    clientSocket.sendto(message.encode(), serverAddress)

    # receive response from the server
    # 1024 is a suggested packet size
    data , server = clientSocket.recvfrom(1024)
    receivedMessage = data.decode()

    # Check if the server sends a new port
    if receivedMessage.startswith("NEWPORT"):
        receivedMessage = receivedMessage.split(" ")
        new_port = int(receivedMessage[1])
        print(f"[recv] Switching to new port {new_port} for further communication.")
        serverAddress = (serverHost, new_port)
        # Combine the rest of the message after the port
        receivedMessage = " ".join(receivedMessage[2:])  # Start from the 2nd index to skip the port

    print(f"[recv] {receivedMessage}")
    if receivedMessage == "Authentication successful, you're active, welcome to BitTrickle":
        authenticated = True
 
if authenticated:
    # Start the heartbeat thread after successful authentication
    heartbeat_running = True
    heartbeat_thread = threading.Thread(target=send_heartbeat)
    heartbeat_thread.start()

    # Start upload server thread, in case peer want to file
    upload_server_thread = Thread(target=start_file_upload, daemon=True)
    upload_server_thread.start()
    
    while True:

        command = input("\nIntroduce the command:   ")
        print(f"[send] {command}")

        if command == "xit":
            # Terminate heartbeat, close sockets
            heartbeat_running = False
            clientSocket.close()
            print("Goodbye")
            break

        if command == None:
                command = "<Empty>"

        clientSocket.sendto(f"{command}".encode(), serverAddress)

        data , server = clientSocket.recvfrom(1024)
        receivedMessage = data.decode()
        print(f"[recv] {receivedMessage}")
        if command.split(" ")[0] == "get":
            if receivedMessage.startswith("PEER"):
                _, peer_ip, peer_port = receivedMessage.split()
                peer_port = int(peer_port)
                download_thread = threading.Thread(target=download_file, args=(peer_ip, peer_port, command.split(" ")[1]))
                download_thread.start()






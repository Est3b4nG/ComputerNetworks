from socket import *
from threading import Thread
import sys
import time

# Acquire server host and port from command line parameter
if len(sys.argv) != 2:
    print("\n===== Error usage, python3 TCPServer3.py SERVER_PORT ======\n")
    exit(0)

serverHost = "127.0.0.1"
serverPort = int(sys.argv[1])
serverAddress = (serverHost, serverPort)

# Define socket for the server side and bind address
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind(serverAddress)

clients= []
client_last_active = {}
activeClients = []
clientUsernamesDict = {}
published_files = {}
TCP_port_dictionaries = {}


class ClientThread(Thread):
    def __init__(self, clientAddress, first_message):
        Thread.__init__(self)
        self.clientAddress = clientAddress
        self.first_message = first_message 

        # Create a dedicated socket for this client (let the OS choose a port)        
        self.clientSocket = socket(AF_INET, SOCK_DGRAM)
        self.clientSocket.bind(('', 0))  # Bind to any available port
        self.clientPort = self.clientSocket.getsockname()[1]  # Get the auto-assigned port

        self.clientAlive = True
        self.clientAuthenticated = False
        
        print("===== New connection created for: ", self.clientAddress)

    def run(self):
        First_iteration = True
        while self.clientAlive:
            try:
                # Receive message from the client
                if First_iteration:
                    message = self.first_message.decode()
                    if "login" in message:
                        print("[recv] New login request")
                        response= self.process_login(message, True)
                    First_iteration = False      
                    # Send the new port to the client for further communication
                    port_message = f"NEWPORT {self.clientPort}"
                    complete_message = f"NEWPORT {self.clientPort} {response}"
                    print(f"[send] {response} to {self.clientAddress}")
                    print(f"[send] {port_message} to {self.clientAddress}")
                    serverSocket.sendto(complete_message.encode(), self.clientAddress)

                else:
                    message, addr = self.clientSocket.recvfrom(1024)
                    if addr != self.clientAddress:
                        continue  # Ignore messages from other clients
                    message = message.decode()
                    #print(message)
                    
                    if self.clientAuthenticated == False:
                        # Handle message from the client                   
                        if "login" in message:
                            print(f"[recv] New login request from {self.clientAddress}")
                            self.process_login(message, False)
                            continue

                        else:
                            print(f"[recv] {message} from {self.clientAddress}")
                            response_message = "Not Valid Option, you need to log in"
                            print(f"[send] {response_message} to {self.clientAddress}")
                            self.clientSocket.sendto(response_message.encode(), self.clientAddress)

                    elif self.clientAuthenticated == True: 

                        if clientUsernamesDict[self.clientAddress] not in activeClients:
                            activeClients.append(clientUsernamesDict[self.clientAddress])

                        client_last_active[clientUsernamesDict[self.clientAddress]] = time.time()
                        
                        if message == 'heartbeat':
                            #print("heartbeat")
                            continue

                        print(f"[recv] {message} from {clientUsernamesDict[self.clientAddress]}")

                        if "upload port" in message:
                            TCP_port_dictionaries[message.split(" ")[0]] = message.split(" ")[5]
                            print(f"[info] {message.split(" ")[0]} upload port {message.split(" ")[5]} added to the TCP port list")
                            #print(TCP_port_dictionaries)  
                            continue    

                        elif message.startswith("pub"):
                            response = self.pubFile(message)

                        elif message.startswith("get"):
                            response = self.getFile(message)
                        
                        elif message.startswith("unp"):
                            response = self.unpFile(message)
                        
                        elif message == "lap":
                            response = self.lap()

                        elif message == "lpf":
                            response = self.lpf()
                        
                        elif message.startswith("sch"):
                            response = self.sch(message)

                        else:  
                            response= 'Cannot understand this message'
                        
                        print(f"[send] {response} to {clientUsernamesDict[self.clientAddress]}")
                        self.clientSocket.sendto(response.encode(), self.clientAddress)

                        
            except Exception as e:
                print("Error: ", e)
                self.clientAlive = False


    def process_login(self, message, first_iteration):
        print("--- Processing Login ---")
        credentials = {}
        try:
            with open("credentials.txt", "r") as file:
                for line in file:
                    username, password = line.strip().split(" ")
                    credentials[username] = password
        except FileNotFoundError:
            print("Error: credentials.txt was not found.")
            sys.exit(1)
        
        # Parse the login message
        login, client_username, client_password = message.strip().split(" ")

        # Authentication checks
        if client_username == "<Empty>" or client_password == "<Empty>":
            response = "Username or password cannot be empty"
        elif client_username not in credentials:
            response = "Wrong username"
        elif credentials[client_username] != client_password:
            response = "Username and password do not correspond"
        else:
            self.clientAuthenticated = True
            clientUsernamesDict[self.clientAddress] = client_username
            if clientUsernamesDict[self.clientAddress] not in activeClients:
                activeClients.append(clientUsernamesDict[self.clientAddress])
            #print(clientUsernamesDict)
            response = "Authentication successful, you're active, welcome to BitTrickle"

        if first_iteration:
            return response
        
        else:    
            print(f"[send] {response} to {self.clientAddress}")
            self.clientSocket.sendto(response.encode(), self.clientAddress)

    def pubFile(self, message):
        filename = message.split(" ")[1]
        if filename not in published_files:
            published_files[filename] = clientUsernamesDict[self.clientAddress] 
            response = f"File {filename} published successfully"
        else:
            response = f"File {filename} is already published"  # Idempotent behavior
        return response

    def getFile(self, message):
        filename = message.split(" ")[1]
        if filename in published_files and published_files[filename] in activeClients:
            for client_address, client_user in clientUsernamesDict.items():
                if client_user == published_files[filename]:
                    peer_address = client_address
                    selected_user = client_user
                    break
            response = f"PEER {peer_address[0]} {TCP_port_dictionaries[selected_user]}"
        else:
            response = "No active peers with that file"
        return response

    def unpFile(self, message):
        filename = message.split(" ")[1]
        if filename in published_files and published_files[filename] == clientUsernamesDict[self.clientAddress]:
            del published_files[filename]
            response = f"The file {filename} was unpublished successfully"
        else:
            response = f"Unpublish failed: No file named {filename} published by this user."
        return response

    def lap(self):
        active_usernames = []
        for user in activeClients:
            if user != clientUsernamesDict[self.clientAddress]:
                active_usernames.append(user)
        if active_usernames:
            response = " , ".join(active_usernames)
        else:
            response = "There are not active peers"
        return response

    def lpf(self):
        clientpublished = []
        for file in published_files:
            if published_files[file] == clientUsernamesDict[self.clientAddress]:
                clientpublished.append(file)
        if clientpublished:
            response = ", ".join(clientpublished)
        else:
            response = "User has not published any file"
        return response
    
    def sch(self, message):
        filesubstring = message.split(" ")[1]
        substring_list = []
        for file in published_files:
            if filesubstring in file and published_files[file] in activeClients and published_files[file]!=clientUsernamesDict[self.clientAddress]:
                substring_list.append(file)
        if substring_list:
            response = " , ".join(substring_list)
        else:
            response = f"There are not files published by peers with {filesubstring} substring"
        return response


print("\n===== Server is running =====")
print("===== Waiting for connection request from clients...=====")


# Periodically check if clients are still active
def check_active_clients():
    while True:
        now = time.time()
        inactive_clients = []

        for client, last_seen in client_last_active.items():
            if now - last_seen > 3:
                activeClients.remove(client)
                inactive_clients.append(client)
        
        for client in inactive_clients:
            print(f"Client {client} is inactive, removing them from active user list.")
            del client_last_active[client]

        #print(activeClients)

        #It is a good practice to add a pauce in order to avoid that the loop continuously consume CPU resources
        time.sleep(0.5)

# Start a thread to monitor active clients
active_check_thread = Thread(target=check_active_clients)
active_check_thread.start()

while True:
    # Wait for a message from any client
    message, clientAddress = serverSocket.recvfrom(1024)

    if clientAddress not in clients:
        clients.append(clientAddress)  # Add the client to the set
        clientThread = ClientThread(clientAddress, message)
        clientThread.start()

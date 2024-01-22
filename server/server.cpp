#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <algorithm>

#include "../security/Util.h"
#include "../security/crypto.h"
#include "../packets/wrapper.h"
#include "../packets/upload.h"
#include "../packets/download.h"
#include "../packets/list.h"
#include "../packets/logout.h"
#include "../tools/file.h"
#include "../packets/rename.h"
#include "../packets/delete.h"
#include <filesystem>
#include <signal.h>
#include "worker.h"

int main()
{
    // Create socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        std::cerr << "[SERVER] Error creating server socket" << std::endl;
        return -1;
    }

    // Bind socket to port
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(ServerDetails::PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        std::cerr << "[SERVER] Error binding socket to port " << ServerDetails::PORT << std::endl;
        close(server_socket);
        return -1;
    }

    // Listen for connections
    if (listen(server_socket, 5) == -1)
    {
        std::cerr << "[SERVER] Error listening for connections" << std::endl;
        close(server_socket);
        return -1;
    }

    std::cout << "[SERVER] listening on port " << ServerDetails::PORT << "..." << std::endl;

    while (true)
    {
        // Accept connection
        sockaddr_in client_addr{};
        socklen_t clientAddrLen = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &clientAddrLen);
        if (client_socket == -1)
        {
            std::cerr << "[SERVER] Error accepting connection" << std::endl;
            continue;
        }

        // Create a new thread for each connected client
        std::thread t1([&client_socket]()
                       { Worker worker = Worker(client_socket);
                       worker.start(); });
        t1.detach();
    }

    // Close server socket (This part will never be reached in this example)
    close(server_socket);

    return 0;
}
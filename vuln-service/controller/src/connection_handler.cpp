#include "connection_handler.hpp"
#include "utils.hpp"
#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <netdb.h>  // for getaddrinfo

#define BUFFER_SIZE 1024

using namespace std;

int ConnectionHandler::create_socket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        cerr << "Could not create socket" << endl;
        exit(EXIT_FAILURE);
    }
    return sock;
}

int ConnectionHandler::close_socket(int sock) {
    if (close(sock) == -1) {
        cerr << "Could not close socket" << endl;
    }
}


void ConnectionHandler::connect_to_server(int sock, const char* hostname, int port) {
    struct addrinfo hints, *res, *p;
    int status;
    char port_str[6];  // Max port number is 65535 (5 digits) + null terminator

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;      // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP socket

    // Convert port number to string
    snprintf(port_str, sizeof(port_str), "%d", port);

    // Perform DNS lookup
    if ((status = getaddrinfo(hostname, port_str, &hints, &res)) != 0) {
        cerr << "DNS lookup failed: " << gai_strerror(status) << endl;
        close(sock);
        return;
    }

    // Try each address until we successfully connect
    for (p = res; p != nullptr; p = p->ai_next) {
        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            // Success
            cout << "Connected to server: " << hostname << ":" << port << endl;
            freeaddrinfo(res);  // Free the linked list
            return;
        }
    }

    // If we get here, all addresses failed
    cerr << "Connection failed to all addresses for: " << hostname << endl;
    freeaddrinfo(res);  // Free the linked list
    close(sock);
}

void ConnectionHandler::receive_response(int sock, std::string & output) {
    char buffer[BUFFER_SIZE] = {0};
    memset(buffer, 0, BUFFER_SIZE);
    int valread = read(sock, buffer, BUFFER_SIZE);
    if (valread <= 0) {
        close(sock);
        return;
    }

    output = buffer;
}


void ConnectionHandler::send_all(int sock, const char* data, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        ssize_t n = send(sock, data + sent, length - sent, 0);
        if (n < 0) {
            cerr << "Send failed" << endl;
            close(sock);
            return;
        }
        sent += n;
    }
}
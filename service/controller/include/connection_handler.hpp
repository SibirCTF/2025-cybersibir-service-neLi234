#ifndef CONNECTION_HANDLER_HPP
#define CONNECTION_HANDLER_HPP

#include <string>
#include <vector>
#include <functional>
#include <sqlite3.h>

class ConnectionHandler {
public:
    static int create_socket();
    static void connect_to_server(int sock, const char* ip, int port);
    static int close_socket(int sock);
    static void receive_response(int sock, std::string & output);
    static void send_all(int sock, const char* data, size_t length);

};

#endif // CONNECTION_HANDLER_HPP
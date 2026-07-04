#ifndef SERVER_HPP
#define SERVER_HPP

#include <netinet/in.h>
#include <mutex>

class Server {
public:
    Server(int port);
    ~Server();
    void run();
    
private:
    static const int BUFFER_SIZE = 1024;
    int port_;
    int server_fd_;
    struct sockaddr_in address_;
    std::mutex console_mutex;
    std::mutex db_mutex;  // Add this line
    
    void handle_client(int client_socket, sockaddr_in client_address);
    void setup_server();
};

#endif // SERVER_HPP
#include "server.hpp"
#include "database_handler.hpp"
#include "connection_handler.hpp"
#include "utils.hpp"
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <vector>
#include <cstring>

Server::Server(int port) : port_(port) {
    setup_server();
}

Server::~Server() {
    close(server_fd_);
}

void Server::setup_server() {
    int opt = 1;
    
    if ((server_fd_ = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address_.sin_family = AF_INET;
    address_.sin_addr.s_addr = INADDR_ANY;
    address_.sin_port = htons(port_);

    if (bind(server_fd_, (struct sockaddr *)&address_, sizeof(address_)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd_, 5) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "Server listening on port " << port_ << std::endl;
}

std::string command_01(int sock, std::string username, std::string problem, std::string solution) {
    // cout << "Enter username: ";
    // getline(cin, username);
    // cout << "Enter string1: ";
    // getline(cin, str1);
    // cout << "Enter string2: ";
    // getline(cin, str2);

    // Build command with null delimiters
    std::string send_data;
    send_data += '\x01';
    send_data += username;
    send_data += '\x01';
    send_data += problem;
    send_data += '\x01';
    send_data += solution;
    send_data += '\n';
    ConnectionHandler::send_all(sock, send_data.c_str(), send_data.size());

    std::string response;
    ConnectionHandler::receive_response(sock, response);
    return response;
}

std::vector<std::string> command_02(int sock, std::string data) {
    std::string send_data;
    send_data += '\x02';
    send_data += data;
    send_data += '\n';

    ConnectionHandler::send_all(sock, send_data.c_str(), send_data.size());
    std::string response;
    ConnectionHandler::receive_response(sock, response);
    std::vector<std::string> fields = utils::parse_delimited(response, '\x01');
    
    return fields;
}

void Server::handle_client(int client_socket, sockaddr_in client_address) {
    char buffer[BUFFER_SIZE] = {0};
    std::string current_user;

    // Authentication phase
    bool authenticated = false;
    while (!authenticated) {
        // Send options to client
        std::string prompt = "Choose an option:\n1. Register\n2. Login\n";
        send(client_socket, prompt.c_str(), prompt.size(), 0);

        // Get client choice
        memset(buffer, 0, BUFFER_SIZE);
        int valread = read(client_socket, buffer, BUFFER_SIZE);
        if (valread <= 0) {
            close(client_socket);
            return;
        }
        std::string choice = utils::trim(buffer);

        if (choice == "1") {
            // Registration
            std::string prompt_username = "Enter username: ";
            send(client_socket, prompt_username.c_str(), prompt_username.size(), 0);

            memset(buffer, 0, BUFFER_SIZE);
            valread = read(client_socket, buffer, BUFFER_SIZE);
            if (valread <= 0) {
                close(client_socket);
                return;
            }
            std::string username = utils::trim(buffer);

            std::string prompt_password = "Enter password: ";
            send(client_socket, prompt_password.c_str(), prompt_password.size(), 0);

            memset(buffer, 0, BUFFER_SIZE);
            valread = read(client_socket, buffer, BUFFER_SIZE);
            if (valread <= 0) {
                close(client_socket);
                return;
            }
            std::string password = utils::trim(buffer);

            {
                std::lock_guard<std::mutex> db_lock(this->db_mutex);
                if (DatabaseHandler::register_user(username, password)) {
                    send(client_socket, "Registration successful!\n", 25, 0);
                } else {
                    send(client_socket, "Registration failed (username may exist)\n", 39, 0);
                }
            }
        }
        else if (choice == "2") {
            // Login
            std::string prompt_username = "Username: ";
            send(client_socket, prompt_username.c_str(), prompt_username.size(), 0);

            memset(buffer, 0, BUFFER_SIZE);
            valread = read(client_socket, buffer, BUFFER_SIZE);
            if (valread <= 0) {
                close(client_socket);
                return;
            }
            std::string username = utils::trim(buffer);

            std::string prompt_password = "Password: ";
            send(client_socket, prompt_password.c_str(), prompt_password.size(), 0);

            memset(buffer, 0, BUFFER_SIZE);
            valread = read(client_socket, buffer, BUFFER_SIZE);
            if (valread <= 0) {
                close(client_socket);
                return;
            }
            std::string password = utils::trim(buffer);

            {
                std::lock_guard<std::mutex> db_lock(this->db_mutex);
                authenticated = DatabaseHandler::authenticate_user(username, password);
            }

            if (authenticated) {
                current_user = username;
                send(client_socket, "Login successful!\n", 18, 0);
            } else {
                send(client_socket, "Login failed\n", 13, 0);
            }
        }
        else {
            send(client_socket, "Invalid option\n", 15, 0);
        }
    }

    // Command handling phase
    while (authenticated) {
        memset(buffer, 0, BUFFER_SIZE);
        int valread = read(client_socket, buffer, BUFFER_SIZE);
        if (valread <= 0) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << "Client disconnected: " << current_user << std::endl;
            break;
        }

        std::string command(buffer);
        command = utils::trim(command);

        // Parse command
        size_t space_pos = command.find(' ');
        std::string cmd = space_pos != std::string::npos ? command.substr(0, space_pos) : command;
        std::string data = space_pos != std::string::npos ? command.substr(space_pos + 1) : "";
        if (cmd == "add" && !data.empty()) {
            {
                std::lock_guard<std::mutex> db_lock(this->db_mutex);
                if (DatabaseHandler::add_message(current_user, data)) {
                    send(client_socket, "Added successfully\n", 19, 0);
                } else {
                    send(client_socket, "Failed to add\n", 14, 0);
                }
            }
        }
        else if (cmd == "get" && !data.empty()) {
            std::string result;
            {
                std::lock_guard<std::mutex> db_lock(this->db_mutex);
                result = DatabaseHandler::get_message(current_user, data);
            }
            
            if (!result.empty()) {
                send(client_socket, ("Found: " + result + "\n").c_str(), result.size() + 8, 0);
            } else {
                send(client_socket, "Not found\n", 10, 0);
            }
        }
        else if (cmd == "getall") {
            std::vector<std::string> result;
            {
                std::lock_guard<std::mutex> db_lock(this->db_mutex);
                result = DatabaseHandler::get_all_messages(current_user, data);
            }
            
            if (!result.empty()) {
                std::string res_string;
                for (auto i : result) {
                    res_string += i + "\n";
                }
                send(client_socket, ("Found: \n" + res_string + "\n").c_str(), res_string.size() + 8, 0);
            } else {
                send(client_socket, "Not found\n", 10, 0);
            }
        }
        else if (cmd == "internalize" && !data.empty()) {
            std::vector<std::string> concept = utils::parse_delimited(data, '=');
            if (concept.size() != 2) {
                send(client_socket, "Invalid command\n", 16, 0);
            }
            int socket = ConnectionHandler::create_socket();
            ConnectionHandler::connect_to_server(socket, "neurolink", 8080);
            std::string internalized = command_01(socket, current_user, concept[0], concept[1]);
            // ConnectionHandler::close_socket(socket);
            std:: string send_data = "Internalized: " + internalized;
            send(client_socket, send_data.c_str(), send_data.length(), 0);
        }
        else if (cmd == "eject" && !data.empty()) {
            // Optionally also store in database:
            int socket = ConnectionHandler::create_socket();
            ConnectionHandler::connect_to_server(socket, "neurolink", 8080);
            std::vector<std::string> ejected_concept = command_02(socket, data);
            std::cout << "here" << std::endl;
            std::cout << "Ejected: " + ejected_concept[1] + "=" + ejected_concept[2] << std::endl;
            // ConnectionHandler::close_socket(socket);
            std:: string send_data = "Ejected: " + ejected_concept[1] + "=" + ejected_concept[2];
            send(client_socket, send_data.c_str(), send_data.length(), 0);
        }
        else {
            send(client_socket, "Invalid command\n", 16, 0);
        }
    }

    close(client_socket);
}

void Server::run() {
    std::vector<std::thread> client_threads;
    
    while (true) {
        int new_socket;
        struct sockaddr_in client_address;
        socklen_t client_addrlen = sizeof(client_address);
        if ((new_socket = accept(server_fd_, (struct sockaddr *)&client_address, &client_addrlen)) < 0) {
            perror("Accept failed");
            continue;
        }

        client_threads.emplace_back(&Server::handle_client, this, new_socket, client_address);
        client_threads.back().detach();
    }
}
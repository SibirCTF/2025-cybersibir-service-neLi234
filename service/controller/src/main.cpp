#include "server.hpp"
#include "database_handler.hpp"
#include <iostream>

int main() {
    DatabaseHandler::initialize_database();
    
    const int PORT = 2340;
    Server server(PORT);
    server.run();
    
    return 0;
}
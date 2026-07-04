#include "database_handler.hpp"
#include <iostream>
#include <functional>
#include <mutex>
#include <algorithm>
#include <cctype>
#include <utility>

const char* DatabaseHandler::DB_FILE = "messages.db";
std::mutex DatabaseHandler::db_mutex;

// Helper structure for callback data
struct CallbackData {
    std::function<int(void*, int, char**, char**)> func;
    void* user_data;
};

// Callback wrapper implementation
static int sql_callback_wrapper(void* data, int argc, char** argv, char** colNames) {
    CallbackData* cb_data = static_cast<CallbackData*>(data);
    if (cb_data && cb_data->func) {
        return cb_data->func(cb_data->user_data, argc, argv, colNames);
    }
    return SQLITE_ERROR;
}

std::string DatabaseHandler::sanitize_sql_input(const std::string& input) {
    std::string output;
    output.reserve(input.length());
    int8_t counter = 0;
    for (char c : input) {
        switch (c) {
            case '\'': output += "''"; break;
            case ';': break;
            case '-':
                if (!output.empty() && (output.back() == '-')) output.pop_back();
                else output += c;
                break;
            default:
                output += c;
                break;
        }
    }
    return output;
}

void DatabaseHandler::initialize_database() {
    sqlite3* db;
    char* err_msg = nullptr;

    if (sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }

    const char* sql_users = 
        "CREATE TABLE IF NOT EXISTS Users ("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
        "Username TEXT NOT NULL UNIQUE, "
        "PasswordHash TEXT NOT NULL);";

    const char* sql_messages = 
        "CREATE TABLE IF NOT EXISTS Thoughts ("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
        "Username TEXT NOT NULL, "
        "Thought TEXT NOT NULL, "
        "Ad TEXT NOT NULL, "
        "FOREIGN KEY(Username) REFERENCES Users(Username));";

    if (sqlite3_exec(db, sql_users, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        std::cerr << "SQL error (Users): " << err_msg << std::endl;
        sqlite3_free(err_msg);
    }

    if (sqlite3_exec(db, sql_messages, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        std::cerr << "SQL error (Messages): " << err_msg << std::endl;
        sqlite3_free(err_msg);
    }

    sqlite3_close(db);
}

std::string DatabaseHandler::simple_hash(const std::string& str) {
    std::hash<std::string> hasher;
    return std::to_string(hasher(str));
}

bool DatabaseHandler::execute_sql(const std::string& sql, 
                                std::function<int(void*, int, char**, char**)> callback,
                                void* callback_data) {
    std::lock_guard<std::mutex> lock(db_mutex);
    sqlite3* db;
    char* err_msg = nullptr;

    if (sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    CallbackData cb_data{callback, callback_data};
    int rc = sqlite3_exec(db, sql.c_str(), sql_callback_wrapper, &cb_data, &err_msg);

    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << (err_msg ? err_msg : "unknown error") << std::endl;
        if (err_msg) sqlite3_free(err_msg);
        sqlite3_close(db);
        return false;
    }

    sqlite3_close(db);
    return true;
}

bool DatabaseHandler::register_user(const std::string& username, const std::string& password) {
    std::string safe_username = sanitize_sql_input(username);
    std::string safe_password = simple_hash(password);
    
    std::string sql = "INSERT INTO Users (Username, PasswordHash) VALUES ('" + 
                     safe_username + "', '" + safe_password + "');";
    return execute_sql(sql);
}

bool DatabaseHandler::authenticate_user(const std::string& username, const std::string& password) {
    struct AuthResult {
        std::string stored_hash;
        std::string input_hash;
        
        AuthResult(const std::string& pwd) : input_hash(simple_hash(pwd)) {}
    } auth_result(password);

    auto callback = [](void* data, int argc, char** argv, char**) -> int {
        AuthResult* result = static_cast<AuthResult*>(data);
        if (argc > 0 && argv[0]) {
            result->stored_hash = argv[0];
        }
        return 0;
    };

    std::string safe_username = sanitize_sql_input(username);
    std::string sql = "SELECT PasswordHash FROM Users WHERE Username = '" + 
                     safe_username + "';";

    if (!execute_sql(sql, callback, &auth_result)) {
        return false;
    }

    return auth_result.stored_hash == auth_result.input_hash;
}

bool DatabaseHandler::add_intrusive_thought(const std::string& username, const std::string& thought, const std::string& ad) {
    std::string safe_username = sanitize_sql_input(username);
    std::string safe_thought = sanitize_sql_input(thought);
    std::string safe_ad = sanitize_sql_input(ad);
    std::string sql = "INSERT INTO Thoughts (Username, Thought, Ad) VALUES ('" + 
                     safe_username + "', '" + safe_thought + "', '" + safe_ad + "');";
    return execute_sql(sql);
}

std::string DatabaseHandler::get_ad(const std::string& username, const std::string& message) {
    struct MessageResult {
        std::string content;
    } result;

    auto callback = [](void* data, int argc, char** argv, char**) -> int {
        MessageResult* res = static_cast<MessageResult*>(data);
        if (argc > 0 && argv[0]) {
            res->content = argv[0];
        }
        return 0;
    };

    std::string safe_username = sanitize_sql_input(username);
    std::string safe_thought = sanitize_sql_input(message);
    
    std::string sql = "SELECT Ad FROM Thoughts WHERE Username = '" + 
                     safe_username + "' AND Thought = '" + safe_thought + "';";

    execute_sql(sql, callback, &result);
    return result.content;
}

std::vector<std::string> DatabaseHandler::get_all_ads(const std::string& username, const std::string& message) {
    struct MessagesResult {
        std::vector<std::string> messages;
    } result;

    auto callback = [](void* data, int argc, char** argv, char**) -> int {
        MessagesResult* res = static_cast<MessagesResult*>(data);
        if (argc > 0 && argv[0]) {
            res->messages.push_back(argv[0]);
        }
        return 0;
    };

    std::string safe_username = sanitize_sql_input(username);
    std::string sql = "SELECT Ad FROM Thoughts WHERE Username = '" + 
                     safe_username;
    if (!message.empty()) {
        std::string safe_message = sanitize_sql_input(message);
        sql += "' AND Thought LIKE '" + safe_message + "' ORDER BY ID ASC;";
    }
    else {
        sql += "' ORDER BY ID ASC;";
    }

    execute_sql(sql, callback, &result);
    return result.messages;
}

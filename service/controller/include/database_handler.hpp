#ifndef DATABASE_HANDLER_HPP
#define DATABASE_HANDLER_HPP

#include <string>
#include <vector>
#include <mutex>
#include <functional>
#include <sqlite3.h>

class DatabaseHandler {
public:
    static void initialize_database();
    
    static bool register_user(const std::string& username, const std::string& password);
    static bool authenticate_user(const std::string& username, const std::string& password);
    
    static bool add_intrusive_thought(const std::string& username, const std::string& thought, const std::string& ad);
    static std::string get_ad(const std::string& username, const std::string& message);
    static std::vector<std::string> get_all_ads(const std::string& username, const std::string& message);

private:
    static const char* DB_FILE;
    static std::mutex db_mutex;
    
    static std::string sanitize_sql_input(const std::string& input);
    static std::string simple_hash(const std::string& str);
    
    static bool execute_sql(const std::string& sql, 
                          std::function<int(void*, int, char**, char**)> callback = nullptr,
                          void* callback_data = nullptr);
};

#endif // DATABASE_HANDLER_HPP
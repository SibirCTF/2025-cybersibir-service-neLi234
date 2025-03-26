#include "utils.hpp"
#include <algorithm>
#include <cctype>
#include <iostream>
#include <string>
#include <vector>

namespace utils {
    std::string trim(const std::string& str) {
        std::string s = str;
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
            return !std::isspace(ch);
        }));
        s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
            return !std::isspace(ch);
        }).base(), s.end());
        return s;
    }

    std::vector<std::string> parse_delimited(const std::string& data, char delimiter) {
        std::vector<std::string> fields;
        size_t start = 0;
        size_t end = data.find(delimiter);
        
        while (end != std::string::npos) {
            fields.push_back(data.substr(start, end - start));
            start = end + 1;
            end = data.find(delimiter, start);
        }
        
        // Add the remaining part after last null byte
        if (start < data.length()) {
            fields.push_back(data.substr(start));
        }
        return fields;
    }
}
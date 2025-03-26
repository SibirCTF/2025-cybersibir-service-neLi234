#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <vector>

namespace utils {
    std::string trim(const std::string& str);
    std::vector<std::string> parse_delimited(const std::string& data, char delimiter);
}

#endif // UTILS_HPP
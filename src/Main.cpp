#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <map>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;

// Forward declaration of decoding functions
json decode_bencoded_value(std::string& encoded_value, int& index);

// Decodes integers in the bencoded format
json decode_integer(std::string& encoded_value, int& index) {
    int end = encoded_value.find('e', index);
    if (end == std::string::npos) {
        throw std::runtime_error("Invalid integer format: 'e' not found.");
    }
    std::string value = encoded_value.substr(index + 1, end - index - 1); // Corrected
    long long num = std::stoll(value);
    index = end + 1;
    return json(num);
}

// Decodes strings in the bencoded format
json decode_string(std::string& encoded_value, int& index) {
    size_t colon_index = encoded_value.find(':', index);
    if (colon_index == std::string::npos) {
        throw std::runtime_error("Invalid string format: ':' not found.");
    }
    std::string number_string = encoded_value.substr(index, colon_index - index);
    int64_t number = std::stoll(number_string);  // Use stoll instead of atoll for better error handling
    std::string str = encoded_value.substr(colon_index + 1, number);
    index = colon_index + number + 1;
    return json(str);
}

// Decodes lists in the bencoded format
json decode_list(std::string& encoded_value, int& index) {
    index++; // Skip 'l'
    std::vector<json> decoded_values;
    while (encoded_value[index] != 'e') {
        decoded_values.push_back(decode_bencoded_value(encoded_value, index)); 
    }
    index++; // Skip 'e'
    return json(decoded_values);
}

// Decodes bencoded values (dispatcher function)
json decode_bencoded_value(std::string& encoded_value, int& index) {
    if (std::isdigit(encoded_value[index])) {
        // Handle string decoding (e.g., "5:hello")
        return decode_string(encoded_value, index);
    } else if (encoded_value[index] == 'i') {
        // Handle integer decoding (e.g., "i123e")
        return decode_integer(encoded_value, index);
    } else if (encoded_value[index] == 'l') {
        // Handle list decoding (e.g., "l5:helloi456ee")
        return decode_list(encoded_value, index);
    } else {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}

int main(int argc, char* argv[]) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "decode") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }

        // Parse the encoded bencoded string
        std::string encoded_value = argv[2];
        int index = 0;
        try {
            json decoded_value = decode_bencoded_value(encoded_value, index);
            std::cout << decoded_value.dump() << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;

json decode_bencoded_value(std::string& encoded_value, int& index);

json decode_integer(std::string& encoded_value, int& index) {
    int end = encoded_value.find('e', index);
    std::string value = encoded_value.substr(index+1, end);
    long long num = stoll(value);
    index = end +1;
    return json(num);
}

json decode_string(std::string encoded_value, int& index) {
    size_t colon_index = encoded_value.find(':');
    if (colon_index != std::string::npos) {
        std::string number_string = encoded_value.substr(index, colon_index);
        int64_t number = std::atoll(number_string.c_str());
        std::string str = encoded_value.substr(colon_index + 1, number);
        index = colon_index + number +1;
        return json(str);
    } else {
        throw std::runtime_error("Invalid encoded value: " + encoded_value);
    }
}

json decode_list(std::string& encoded_value, int& index) {
    if (encoded_value[index] != 'l') {
        throw std::runtime_error("Expected 'l' at index: " + std::to_string(index));
    }

    index++; // Move past 'l'
    std::vector<json> decoded_values;

    while (index < encoded_value.size() && encoded_value[index] != 'e') {
        decoded_values.push_back(decode_bencoded_value(encoded_value, index));
    }

    if (index >= encoded_value.size() || encoded_value[index] != 'e') {
        throw std::runtime_error("Unterminated list at index: " + std::to_string(index));
    }

    index++; // Move past 'e'
    return json(decoded_values);
}

json decode_dict(std::string encoded_value, int& index) {
    index++;
    std::map<json, json> mp;

    while(encoded_value[index] != 'e') {
        json key = decode_bencoded_value(encoded_value, index);
        json value = decode_bencoded_value(encoded_value, index);
        mp[key] = value;
    }
    index++;

    return json(mp);
}


json decode_bencoded_value(std::string& encoded_value, int& index) {
    // int index = 0;
    if (std::isdigit(encoded_value[index])) {
        // Example: "5:hello" -> "hello"
        return decode_string(encoded_value, index);
    } else if(encoded_value[index] == 'i') {
        return decode_integer(encoded_value, index);
    } else if(encoded_value[index] == 'l') {
        return decode_list(encoded_value, index);
    } else if(encoded_value[index] == 'd') {
        return decode_dict(encoded_value, index);
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
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        std::cerr << "Logs from your program will appear here!" << std::endl;

        // Uncomment this block to pass the first stage
        std::string encoded_value = argv[2];
        int index = 0;
        json decoded_value = decode_bencoded_value(encoded_value, index);
        std::cout << decoded_value.dump() << std::endl;
    } else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}

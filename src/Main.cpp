#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include "lib/sha1.hpp"
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
    size_t colon_index = encoded_value.find(':', index);
    if (colon_index != std::string::npos) {
        std::string number_string = encoded_value.substr(index, colon_index - index);
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

    while(index<encoded_value.size() && encoded_value[index] != 'e') {
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

std::string json_to_bencode(const json& j) {
    std::ostringstream os;
    if (j.is_object()) {
        os << 'd';
        for (auto& el : j.items()) {
            os << el.key().size() << ':' << el.key() << json_to_bencode(el.value());
        }
        os << 'e';
    } else if (j.is_array()) {
        os << 'l';
        for (const json& item : j) {
            os << json_to_bencode(item);
        }
        os << 'e';
    } else if (j.is_number_integer()) {
        os << 'i' << j.get<int>() << 'e';
    } else if (j.is_string()) {
        const std::string& value = j.get<std::string>();
        os << value.size() << ':' << value;
    }
    return os.str();
}

void print_piece_hashes(json& decoded_value) {
    int n = decoded_value.size();
    for(int i=0;i<n;i+=20) {
        int j=i;
        std::string hash = "";

        for(int j=i;j<i+20;j++) {
            hash += decoded_value[j];
        }

        std::cout<<hash<<std::endl;
    }

    return;
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
    } else if(command == "info") {
        std::string filePath = argv[2];
        std::ifstream file(filePath, std::ios::binary);
        std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        int id = 0;
        json decoded_value = decode_bencoded_value(fileContent, id);
        std::string bencoded_info = json_to_bencode(decoded_value["info"]);
        // std::cout<<bencoded_info<<std::endl;
        SHA1 sha1;
        sha1.update(bencoded_info);
        std::string info_hash = sha1.final();
        std::cout << "Tracker URL: " << decoded_value["announce"].get<std::string>() << std::endl;
        std::cout << "Length: " << decoded_value["info"]["length"].get<int>() << std::endl;
        std::cout << "Info Hash: " << info_hash << std::endl;
        std::cout << "Piece Length: " << decoded_value["info"]["piece length"] << std::endl;
        // std::cout << "Pieces: " << decoded_value["info"]["pieces"] << std::endl;
        print_piece_hashes(decoded_value["info"]["pieces"]);
    } else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}

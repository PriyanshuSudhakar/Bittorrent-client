#include <iostream>
#include <string>
#include <vector>
#include <deque>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include "lib/sha1.hpp"
#include "lib/nlohmann/json.hpp"
#include "lib/HTTP.hpp"
#include "lib/curl.h"
#include <array>
#include <cstring>
#include <random>
#ifdef _WIN32
#include <winsock2.h>
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#pragma comment(lib, "ws2_32.lib") // Link Winsock library
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#define closesocket close
// #include "lib/WinSock2.h"
// #include "lib/WS2tcpip.h"
#endif

using json = nlohmann::json;

struct Handshake
{
    uint8_t length;
    char protocol[19];
    uint8_t reservedBytes[8];
    char infoHash[20];
    char peerID[20];
    Handshake(const std::string &infoHashS, const std::string &peerIDS)
    {
        length = 19;
        std::memcpy(protocol, "BitTorrent protocol", 19);
        std::memset(reservedBytes, 0, 8);
        std::memcpy(infoHash, infoHashS.data(), 20);
        std::memcpy(peerID, peerIDS.data(), 20);
    }
    std::vector<char> toVector() const
    {
        std::vector<char> handshakeVector(sizeof(Handshake), 0);
        std::memcpy(handshakeVector.data(), this, sizeof(Handshake));
        return handshakeVector;
    }
};

struct BlockRequest
{
    int piece_index;
    int offset;
    size_t length;
};

const size_t PIECE_BLOCK = 16384; // 16 kb
enum MessageType : uint8_t
{
    choke = 0,
    unchoke = 1,
    interested = 2,
    not_interested = 3,
    have = 4,
    bitfield = 5,
    request = 6,
    piece = 7,
    cancel = 8
};

void send_message(int sockfd, MessageType messageType, const std::vector<uint8_t> &payload = {})
{
    uint32_t length = htonl(payload.size() + 1);
    send(sockfd, reinterpret_cast<char *>(&length), sizeof(length), 0);
    uint8_t id = static_cast<uint8_t>(messageType);
    send(sockfd, reinterpret_cast<char *>(&id), sizeof(id), 0);
    if (!payload.empty())
    {
        send(sockfd, reinterpret_cast<const char *>(payload.data()), payload.size(), 0);
    }
}
void request_block(int sockfd, int index, int begin, int length)
{
    std::vector<uint8_t> payload(12);
    uint32_t index_n = htonl(index);   // Piece index
    uint32_t begin_n = htonl(begin);   // Block start offset
    uint32_t length_n = htonl(length); // Block length
    // All later integers sent in the protocol are encoded as four bytes big-endian.
    std::memcpy(&payload[0], &index_n, 4);
    std::memcpy(&payload[4], &begin_n, 4);
    std::memcpy(&payload[8], &length_n, 4);
    send_message(sockfd, MessageType::request, payload);
}
// Utility function to parse command-line arguments
std::string get_output_file(int argc, char *argv[])
{
    for (int i = 1; i < argc - 1; ++i)
    {
        if (std::string(argv[i]) == "-o")
        {
            return std::string(argv[i + 1]);
        }
    }
    throw std::runtime_error("Output file not specified. Use the -o option.");
}

std::vector<uint8_t> receive_message(int sockfd)
{
    // Read message length (4 bytes)
    uint32_t length = 0;
    // std::cout << "Message length: " << length << std::endl;
    if (recv(sockfd, reinterpret_cast<char *>(&length), sizeof(length), 0) != sizeof(length)) // failed after downloading some blocks, but why?
    {
        throw std::runtime_error("Failed to read message");
    }
    length = ntohl(length);
    // Read the payload (can ignore this for now)
    std::vector<uint8_t> buffer(length);
    int totalBytesRead = 0;
    while (totalBytesRead < length)
    {
        int bytesRead = recv(sockfd, reinterpret_cast<char *>(buffer.data() + totalBytesRead), length - totalBytesRead, 0);
        if (bytesRead <= 0)
        {
            throw std::runtime_error("Failed to read payload: Connection lost or incomplete data");
        }
        totalBytesRead += bytesRead;
    }
    return buffer;
}

std::string calculateInfohash(std::string bencoded_info)
{
    SHA1 sha1;
    sha1.update(bencoded_info);
    std::string infoHash = sha1.final();
    return infoHash;
}

std::vector<uint8_t> download_piece(int sockfd, size_t pieceIndex, size_t pieceLength, size_t totalPieces, size_t length, const std::string &pieceHashes)
{
    size_t currentPieceSize = (pieceIndex == totalPieces - 1)
                                  ? length % pieceLength
                                  : pieceLength;
    currentPieceSize = (currentPieceSize == 0) ? pieceLength : currentPieceSize;
    size_t remaining = currentPieceSize, offset = 0;
    std::vector<uint8_t> pieceData(currentPieceSize);
    std::deque<BlockRequest> pendingRequests;
    while (remaining > 0 || !pendingRequests.empty())
    {
        while (pendingRequests.size() < 20 && remaining > 0)
        {
            size_t blockSize = std::min(PIECE_BLOCK, remaining);
            request_block(sockfd, pieceIndex, offset, blockSize);
            pendingRequests.push_back({pieceIndex, offset, blockSize});
            offset += blockSize;
            remaining -= blockSize;
        }
        std::vector<uint8_t> message = receive_message(sockfd);
        if (message[0] != MessageType::piece)
        {
            throw std::runtime_error("Expected piece message");
        }
        int index = ntohl(*reinterpret_cast<int *>(&message[1]));
        int begin = ntohl(*reinterpret_cast<int *>(&message[5]));
        const uint8_t *block = &message[9];
        int blockLength = message.size() - 9;
        auto it = std::find_if(pendingRequests.begin(), pendingRequests.end(), [&](const BlockRequest &req)
                               { return req.piece_index == index && req.offset == begin; });
        if (it == pendingRequests.end())
        {
            throw std::runtime_error("Unexpected block received");
        }
        std::memcpy(&pieceData[it->offset], block, blockLength);
        pendingRequests.erase(it);
    }
    // Verify piece hash
    std::string pieceHash = calculateInfohash(std::string(pieceData.begin(), pieceData.end()));
    std::string expectedPieceHash(pieceHashes.begin() + pieceIndex * 20, pieceHashes.begin() + (pieceIndex + 1) * 20);
    if (hex_to_bytes(pieceHash) != expectedPieceHash)
    {
        throw std::runtime_error("Piece hash mismatch");
    }
    return pieceData;
}
void write_to_disk(const std::vector<uint8_t> &fullFileData, int argc, char **argv)
{
    std::string outputFile = get_output_file(argc, argv);
    std::ofstream ofs(outputFile, std::ios::binary);
    if (!ofs || !ofs.write(reinterpret_cast<const char *>(fullFileData.data()), fullFileData.size()))
    {
        throw std::runtime_error("Failed to write data to output file: " + outputFile);
    }
    std::cout << "File written to " << outputFile << std::endl;
}

std::string generate_random_peer_id()
{
    std::string peer_id = "-MY1234-"; // Example prefix
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 35);

    const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    for (size_t i = 0; i < 12; ++i)
    { // Generate remaining 12 characters
        peer_id += charset[dist(gen)];
    }
    return peer_id;
}

json decode_bencoded_value(std::string &encoded_value, int &index);

json decode_integer(std::string &encoded_value, int &index)
{
    int end = encoded_value.find('e', index);
    std::string value = encoded_value.substr(index + 1, end);
    long long num = stoll(value);
    index = end + 1;
    return json(num);
}

json decode_string(std::string encoded_value, int &index)
{
    size_t colon_index = encoded_value.find(':', index);
    if (colon_index != std::string::npos)
    {
        std::string number_string = encoded_value.substr(index, colon_index - index);
        int64_t number = std::atoll(number_string.c_str());
        std::string str = encoded_value.substr(colon_index + 1, number);
        index = colon_index + number + 1;
        return json(str);
    }
    else
    {
        throw std::runtime_error("Invalid encoded value: " + encoded_value);
    }
}

json decode_list(std::string &encoded_value, int &index)
{
    if (encoded_value[index] != 'l')
    {
        throw std::runtime_error("Expected 'l' at index: " + std::to_string(index));
    }

    index++; // Move past 'l'
    std::vector<json> decoded_values;

    while (index < encoded_value.size() && encoded_value[index] != 'e')
    {
        decoded_values.push_back(decode_bencoded_value(encoded_value, index));
    }

    if (index >= encoded_value.size() || encoded_value[index] != 'e')
    {
        throw std::runtime_error("Unterminated list at index: " + std::to_string(index));
    }

    index++; // Move past 'e'
    return json(decoded_values);
}

json decode_dict(std::string encoded_value, int &index)
{
    index++;
    std::map<json, json> mp;

    while (index < encoded_value.size() && encoded_value[index] != 'e')
    {
        json key = decode_bencoded_value(encoded_value, index);
        json value = decode_bencoded_value(encoded_value, index);
        mp[key] = value;
    }
    index++;

    return json(mp);
}

json decode_bencoded_value(std::string &encoded_value, int &index)
{
    // int index = 0;
    if (std::isdigit(encoded_value[index]))
    {
        // Example: "5:hello" -> "hello"
        return decode_string(encoded_value, index);
    }
    else if (encoded_value[index] == 'i')
    {
        return decode_integer(encoded_value, index);
    }
    else if (encoded_value[index] == 'l')
    {
        return decode_list(encoded_value, index);
    }
    else if (encoded_value[index] == 'd')
    {
        return decode_dict(encoded_value, index);
    }
    else
    {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}

std::string json_to_bencode(const json &j)
{
    std::ostringstream os;
    if (j.is_object())
    {
        os << 'd';
        for (auto &el : j.items())
        {
            os << el.key().size() << ':' << el.key() << json_to_bencode(el.value());
        }
        os << 'e';
    }
    else if (j.is_array())
    {
        os << 'l';
        for (const json &item : j)
        {
            os << json_to_bencode(item);
        }
        os << 'e';
    }
    else if (j.is_number_integer())
    {
        os << 'i' << j.get<int>() << 'e';
    }
    else if (j.is_string())
    {
        const std::string &value = j.get<std::string>();
        os << value.size() << ':' << value;
    }
    return os.str();
}

void print_piece_hashes(const json &pieces)
{
    if (!pieces.is_string())
    {
        std::cerr << "Error: 'pieces' is not a string!" << std::endl;
        return;
    }

    std::string piece_hashes = pieces.get<std::string>();
    size_t n = piece_hashes.size();

    if (n % 20 != 0)
    {
        std::cerr << "Error: 'pieces' size is not a multiple of 20!" << std::endl;
        return;
    }

    // Loop through the pieces in chunks of 20 bytes
    for (size_t i = 0; i < n; i += 20)
    {
        std::string hash = piece_hashes.substr(i, 20);

        // Convert hash to a readable hexadecimal format
        for (char c : hash)
        {
            printf("%02x", static_cast<unsigned char>(c));
        }
        std::cout << std::endl;
    }
}

std::string hex_to_bytes(const std::string &hex)
{
    if (hex.length() % 2 != 0)
    {
        throw std::invalid_argument("Invalid hex string length");
    }

    std::string bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        unsigned char byte = std::stoi(hex.substr(i, 2), nullptr, 16);
        bytes.push_back(static_cast<char>(byte));
    }
    return bytes;
}

std::string url_encode(const std::string &data)
{
    std::ostringstream encoded;
    for (unsigned char c : data)
    {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            encoded << c;
        }
        else
        {
            encoded << '%' << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(c);
        }
    }
    return encoded.str();
}

std::pair<std::string, int> parse_peer_info(std::string peer_info)
{
    size_t colonIndex = peer_info.find(':');
    if (colonIndex == std::string::npos)
    {
        throw std::runtime_error("Invalid peer address format");
    }
    std::string peerIP = peer_info.substr(0, colonIndex);
    int peerPort = std::stoi(peer_info.substr(colonIndex + 1));
    return {peerIP, peerPort};
}

int connect_to_peer(const std::string &ip, int port)
{
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "WSAStartup failed" << std::endl;
        return -1;
    }
#endif
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Socket creation failed");
        return -1;
    }
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(ip.c_str());
    if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        closesocket(sockfd);
        throw std::runtime_error("Failed to connect to peer");
    }
    return sockfd;
}

std::string bytes_to_hex(const std::string &bytes)
{
    std::ostringstream hex;
    hex.fill('0');
    hex << std::hex;
    for (unsigned char c : bytes)
    {
        hex << std::setw(2) << static_cast<int>(c);
    }
    return hex.str();
}

void perform_handshake(int sockfd, const std::vector<char> &handshakeMessage, const std::string &binaryInfoHash)
{
    if (send(sockfd, handshakeMessage.data(), handshakeMessage.size(), 0) == -1)
    {
        throw std::runtime_error("Failed to send handshake message");
    }
    char response[68];
    ssize_t bytesRead = recv(sockfd, response, sizeof(response), 0);
    if (bytesRead != 68 || std::string(response + 28, 20) != binaryInfoHash)
    {
        throw std::runtime_error("Invalid handshake response");
    }
    // Step 4: Validate the handshake response
    std::string received_infohash = std::string(response, 68).substr(28, 20);
    if (received_infohash != binaryInfoHash)
    {
        throw std::runtime_error("Invalid handshake response: Infohash mismatch");
    }
    std::cout << "Handshake established" << std::endl;
    /*
    Remember to convert back to hexadecimal for human readable output
    Prints the hexadecimal value of the Peer ID of the Peer that we (the client) connected to
    Example: received_peer_id: 3030313132323333343435353636373738383939 -> peer_id: 116494218e909827af98a36137026979dabbdcb9
    */
    std::string receivedPeerID(std::string(response, 68).substr(48, 20));
    std::cout << "Peer ID: " << bytes_to_hex(receivedPeerID) << std::endl;
}

std::string read_file(const std::string &filePath)
{
    /*
    open the file
    */
    std::ifstream file(filePath, std::ios::binary);
    std::stringstream buffer;
    /*
    read the content from the file
    then close
    */
    if (file)
    {
        buffer << file.rdbuf();
        file.close();
        return buffer.str();
    }
    else
    {
        throw std::runtime_error("Failed to open file: " + filePath);
    }
}

void parse_torrent(const std::string &filePath)
{
    std::string fileContent = read_file(filePath);
    json decoded_torrent = decode_bencoded_value(fileContent);
    // bencode the torrent
    std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);
    // calculate the info hash
    SHA1 sha1;
    sha1.update(bencoded_info);
    std::string infoHash = sha1.final();
    // announceURL
    std::string trackerURL = decoded_torrent["announce"];

    // length
    int length = decoded_torrent["info"]["length"];
    // piece length
    int pieceLength = decoded_torrent["info"]["piece length"];

    std::cout << "Tracker URL: " << trackerURL << std::endl;
    std::cout << "Length: " << length << std::endl;
    std::cout << "Info Hash: " << infoHash << std::endl;
    std::cout << "Piece Length: " << pieceLength << std::endl;
    std::cout << "Piece Hashes: " << std::endl;
    // concatenated SHA-1 hashes of each piece (20 bytes each)
    for (std::size_t i = 0; i < decoded_torrent["info"]["pieces"].get<std::string>().length(); i += 20)
    {
        std::string piece = decoded_torrent["info"]["pieces"].get<std::string>().substr(i, 20);
        std::stringstream ss;
        for (unsigned char byte : piece)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        std::cout << ss.str() << std::endl;
    }
}
std::string generate_tracker_url(const std::string &trackerURL, const std::string &infoHash, const std::string &peerID, size_t length)
{
    std::ostringstream url;
    url << trackerURL << "?info_hash=" << url_encode(infoHash)
        << "&peer_id=" << peerID
        << "&port=6881"
        << "&uploaded=0"
        << "&downloaded=0"
        << "&left=" << length
        << "&compact=1";
    return url.str();
}
std::vector<std::string> parse_peers(const std::string &peers)
{
    std::vector<std::string> result;
    for (size_t i = 0; i < peers.size(); i += 6)
    {
        std::string ip = std::to_string((unsigned char)peers[i]) + "." +
                         std::to_string((unsigned char)peers[i + 1]) + "." +
                         std::to_string((unsigned char)peers[i + 2]) + "." +
                         std::to_string((unsigned char)peers[i + 3]);
        int port = ((unsigned char)peers[i + 4] << 8) | (unsigned char)peers[i + 5];
        result.push_back(ip + ":" + std::to_string(port));
    }
    return result;
}
// Function to perform HTTP GET request
size_t write_callback(void *contents, size_t size, size_t nmemb, std::string *userp)
{
    userp->append(static_cast<char *>(contents), size * nmemb);
    return size * nmemb;
}
std::string http_get(const std::string &url)
{
    CURL *curl;
    CURLcode res;
    std::string response;
    curl = curl_easy_init();
    if (!curl)
        throw std::runtime_error("Failed to initialize CURL");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        curl_easy_cleanup(curl);
        throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
    }
    curl_easy_cleanup(curl);
    return response;
}
std::vector<std::string> request_peers(const std::string &trackerURL, const std::string &infoHash,
                                       const std::string &peerID, size_t length)
{
    std::string trackerResponse = http_get(generate_tracker_url(trackerURL, infoHash, peerID, length));
    int index = 0;
    json decodedResponse = decode_bencoded_value(trackerResponse, index);
    return parse_peers(decodedResponse["peers"]);
}

auto parse_torrent_file(const std::string &filePath)
{
    std::string fileContent = read_file(filePath);
    json decodedTorrent = decode_bencoded_value(fileContent);
    std::string trackerURL = decodedTorrent["announce"];
    size_t length = decodedTorrent["info"]["length"];
    size_t pieceLength = decodedTorrent["info"]["piece length"];
    size_t totalPieces = (length + pieceLength - 1) / pieceLength;
    std::string infoHash = calculateInfohash(json_to_bencode(decodedTorrent["info"]));
    std::string pieceHashes = decodedTorrent["info"]["pieces"];
    return std::make_tuple(decodedTorrent, trackerURL, length, pieceLength, totalPieces, infoHash, pieceHashes);
}

int main(int argc, char *argv[])
{
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "decode")
    {
        if (argc < 3)
        {
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
    }
    else if (command == "info")
    {
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
    }
    else if (command == "peers")
    {
        std::ifstream input_file{argv[2], std::ios::binary};
        if (!input_file)
        {
            std::cerr << "Error opening torrent file: " << argv[2] << std::endl;
            return 1;
        }
        std::vector<char> file_data((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
        std::string_view file_data_view(file_data.data(), file_data.size());
        std::string file_data_str(file_data_view);
        try
        {
            int index = 0;
            SHA1 sha1;
            auto decoded_info = decode_bencoded_value(file_data_str, index);
            std::string bencoded_string = json_to_bencode(decoded_info.at("info"));
            std::string url = decoded_info.at("announce").get<std::string>();
            // SHA1 sha1;
            sha1.update(bencoded_string);
            std::string encoded_info_hash = sha1.final();
            encoded_info_hash = hex_to_bytes(encoded_info_hash);
            encoded_info_hash = url_encode(encoded_info_hash);
            std::string left = std::to_string(file_data.size()); // Convert size_t to string
            std::string peer_id = generate_random_peer_id();
            std::cout << url + "?info_hash=" + encoded_info_hash + "&peer_id=" + peer_id + "&port=6881&uploaded=0&downloaded=0&left=" + left + "&compact=1" << std::endl;
            http::Request request{url + "?info_hash=" + encoded_info_hash + "&peer_id=" + peer_id + "&port=6881&uploaded=0&downloaded=0&left=" + left + "&compact=1"};
            const auto response = request.send("GET");
            std::string response_body{response.body.begin(), response.body.end()};
            std::string_view response_body_view(response_body.data(), response_body.size());
            index = 0;
            std::string response_body_str(response_body_view);
            auto decoded_response = decode_bencoded_value(response_body_str, index);
            std::string peers = decoded_response.at("peers").get<std::string>();
            for (size_t i = 0; i < peers.length(); i += 6)
            {
                std::string ip = std::to_string(static_cast<unsigned char>(peers[i])) + "." +
                                 std::to_string(static_cast<unsigned char>(peers[i + 1])) + "." +
                                 std::to_string(static_cast<unsigned char>(peers[i + 2])) + "." +
                                 std::to_string(static_cast<unsigned char>(peers[i + 3]));
                uint16_t port = (static_cast<uint16_t>(static_cast<unsigned char>(peers[i + 4]) << 8)) | static_cast<uint16_t>(static_cast<unsigned char>(peers[i + 5]));
                std::cout << ip << ":" << port << std::endl;
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }
    else if (command == "handshake")
    {
        std::string filePath = argv[2];
        std::ifstream file(filePath, std::ios::binary);
        std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        try
        {
            std::string peer_info = argv[3];
            auto [peerIP, peerPort] = parse_peer_info(peer_info);
            int index = 0;
            json decoded_torrent = decode_bencoded_value(fileContent, index);
            std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);

            SHA1 sha1;
            sha1.update(bencoded_info);
            std::string encoded_info_hash = sha1.final();
            encoded_info_hash = hex_to_bytes(encoded_info_hash);

            std::string peerID = generate_random_peer_id();

            Handshake handshake(encoded_info_hash, peerID);
            std::vector<char> handshakeMessage = handshake.toVector();
            // Step 1: Establish TCP connection with the peer
            int sockfd = connect_to_peer(peerIP, peerPort);
            perform_handshake(sockfd, handshakeMessage, (encoded_info_hash));
            // close the socket
            closesocket(sockfd);
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
        }
    }
    else if (command == "download_piece")
    {
        std::string filePath = argv[4];
        try
        {
            auto [decoded_torrent, trackerURL, length, pieceLength, totalPieces, infoHash, pieceHashes] = parse_torrent_file(filePath);
            std::string peerID = "01234567890123456789";
            // Perform the tracker GET request to get a list of peers
            // parse the peers and print them
            std::vector<std::string> peerList = request_peers(trackerURL, infoHash, peerID, length);
            // Establish a TCP connection with a peer, and perform a handshake
            Handshake handshake(hex_to_bytes(infoHash), peerID);
            std::vector<char> handshakeMessage = handshake.toVector();

            if (peerList.empty())
            {
                throw std::runtime_error("No peers available for connection");
            }
            // Piece index from command line
            // "./your_bittorrent.sh download_piece -o /tmp/test-piece sample.torrent <piece_index>"
            int piece_index = std::stoi(argv[5]);
            std::string peerInfo = peerList[0];
            // for (const auto& peerInfo : peerList)
            // {
            try
            {
                auto [peerIP, peerPort] = parse_peer_info(peerInfo);
                // Step 1: Establish TCP connection with the peer
                int sockfd = connect_to_peer(peerIP, peerPort);
                perform_handshake(sockfd, handshakeMessage, hex_to_bytes(infoHash));
                // Exchange multiple peer messages to download the file
                // TODO
                // Receive bitfield message
                std::vector<uint8_t> bitfield = receive_message(sockfd);
                if (bitfield[0] != MessageType::bitfield)
                {
                    throw std::runtime_error("Expected bitfield message");
                }
                int byteIndex = piece_index / 8;
                int bitIndex = piece_index % 8;
                if (byteIndex >= bitfield.size() - 1 || !(bitfield[byteIndex + 1] & (1 << (7 - bitIndex))))
                {
                    std::cout << "Peer does not have the requested piece" << std::endl;
                    closesocket(sockfd);
                    // continue;
                }
                std::cout << "Peer has the requested piece. Initiating download..." << std::endl;
                // Send interested message
                send_message(sockfd, MessageType::interested);
                // Receive unchoke message
                std::vector<uint8_t> unchoke = receive_message(sockfd);
                if (unchoke[0] != MessageType::unchoke)
                {
                    throw std::runtime_error("Expected unchoke message");
                }
                // Send request message
                // Divide piece into blocks and request each blocks
                // Receive piece message for each block requested
                // Note: INDEX ALWAYS STARTS FROM ZERO, DO NOT FORGET THIS
                std::vector<uint8_t> pieceData = download_piece(sockfd, piece_index, pieceLength, totalPieces, length, pieceHashes);
                // Write piece to disk
                std::ofstream output(argv[3]);
                output.write(reinterpret_cast<const char *>(pieceData.data()), pieceData.size());
                output.close();
                std::cout << "Piece downloaded successfully" << std::endl;
                closesocket(sockfd);
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error with peer: " << e.what() << std::endl;
                // continue;
            }
            // }
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
        }
    }
    else
    {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}

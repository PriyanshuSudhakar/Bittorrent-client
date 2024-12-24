#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <array>
#include <cstring>
#include "curl/curl.h"
#include <queue>
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib") // Link Winsock library
#include <BaseTsd.h>
typedef SSIZE_T ssize_t; // Define ssize_t for Wind
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#define closesocket close
#endif
#include "lib/nlohmann/json.hpp"
#include "lib/sha1.hpp"

using json = nlohmann::json;

json decode_bencoded_value(const std::string &encoded_value, size_t &index);

json decode_bencoded_string(const std::string &encoded_value, size_t &index)
{

    std::string result = "";
    while (std::isdigit(encoded_value[index]))
    {
        result += encoded_value[index];
        index++;
    }
    int length = std::atoll(result.c_str());
    result = "";
    index++;
    while (length--)
    {
        result += encoded_value[index];
        index++;
    }
    return result;
}

json decode_bencoded_integer(const std::string &encoded_value, size_t &index)
{
    index++;
    std::string result = "";
    while (encoded_value[index] != 'e')
    {
        result += encoded_value[index];
        index++;
    }
    index++;
    return json(std::atoll(result.c_str()));
}

json decode_bencoded_value(const std::string &encoded_value)
{

    size_t index = 0;

    json res = decode_bencoded_value(encoded_value, index);

    if (index != encoded_value.size())
    {

        throw std::runtime_error("String not fully consumed.");
    }

    return res;
}

json decode_bencoded_list(const std::string &encoded_value, size_t &index)
{
    index++;
    json list = json::array();
    while (encoded_value[index] != 'e')
    {
        list.push_back(decode_bencoded_value(encoded_value, index));
    }
    index++;
    return list;
}

json decode_bencoded_dict(const std::string &encoded_value, size_t &index)
{
    index++;
    json res = json::object();
    // skip the 'd'
    while (encoded_value[index] != 'e')
    {
        /*
        d<key1><value1>...<keyN><valueN>
        Example "d3:foo3:bare"
        foo is key, bar is value

        lexicographical order: a generalization of the alphabetical order of the dictionaries to sequences of ordered symbols or,
        more generally, of elements of a totally ordered set.
        */
        json key = decode_bencoded_value(encoded_value, index);
        json value = decode_bencoded_value(encoded_value, index);
        res[key.get<std::string>()] = value;
    }
    index++;
    return res;
}

json decode_bencoded_value(const std::string &encoded_value, size_t &index)
{
    if (std::isdigit(encoded_value[index]))
    {
        // Example: "5:hello" -> "hello"
        return decode_bencoded_string(encoded_value, index);
    }
    else if (encoded_value[index] == 'i')
    {
        // Example: "i45e" - > "45"
        return decode_bencoded_integer(encoded_value, index);
    }
    else if (encoded_value[index] == 'l')
    {
        // Example: "l10:strawberryi559ee" -> "[strawberry, 559]"
        return decode_bencoded_list(encoded_value, index);
    }
    else if (encoded_value[index] == 'd')
    {
        // Example: "d3:foo3:bar5:helloi52ee" -> {"foo":"bar", "hello":"52"}
        return decode_bencoded_dict(encoded_value, index);
    }
    else
    {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
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

std::string json_to_bencode(const json &js)
{
    std::ostringstream os;
    if (js.is_object())
    {
        os << 'd';
        for (auto &el : js.items())
        {
            os << el.key().size() << ':' << el.key() << json_to_bencode(el.value());
        }
        os << 'e';
    }
    else if (js.is_array())
    {
        os << 'l';
        for (const json &item : js)
        {
            os << json_to_bencode(item);
        }
        os << 'e';
    }
    else if (js.is_number_integer())
    {
        os << 'i' << js.get<int>() << 'e';
    }
    else if (js.is_string())
    {
        const std::string &value = js.get<std::string>();
        os << value.size() << ':' << value;
    }
    return os.str();
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

std::string calculateInfohash(std::string bencoded_info)
{
    SHA1 sha1;
    sha1.update(bencoded_info);
    std::string infoHash = sha1.final();
    return infoHash;
}

struct BlockRequest
{
    int piece_index;
    int offset;
    size_t length;
};

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

// Function to convert hexadecimal string to bytes
std::vector<unsigned char> hexToBytes(const std::string &hex)
{
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
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

// Function to encode info_hash in URL-encoded format
std::string url_encode(const std::string &value)
{
    auto rawBytes = hexToBytes(value);

    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : rawBytes)
    {
        if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            escaped << c;
        }
        else
        {
            escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
        }
    }

    return escaped.str();
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

// Function to parse compact peer list
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
    json decodedResponse = decode_bencoded_value(trackerResponse);

    return parse_peers(decodedResponse["peers"]);
}

// Establish connection to the peer
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

// Convert hexadecimal to binary (for InfoHash)
std::string hex_to_binary(const std::string &hex)
{
    if (hex.size() != 40)
    {
        throw std::runtime_error("Invalid SHA1 hash length; expected 40 hex characters.");
    }

    std::string binary;
    binary.reserve(20); // 40 hex characters = 20 bytes binary

    for (size_t i = 0; i < hex.size(); i += 2)
    {
        // Convert each pair of hex characters to a single byte
        unsigned char byte = std::stoul(hex.substr(i, 2), nullptr, 16);
        binary.push_back(static_cast<char>(byte));
    }

    return binary;
}

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

std::pair<std::string, int> parse_peer_info(const std::string &peerInfo)
{
    size_t colonIndex = peerInfo.find(':');
    if (colonIndex == std::string::npos)
    {
        throw std::runtime_error("Invalid peer address format");
    }

    std::string peerIP = peerInfo.substr(0, colonIndex);
    int peerPort = std::stoi(peerInfo.substr(colonIndex + 1));
    return {peerIP, peerPort};
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
    if (hex_to_binary(pieceHash) != expectedPieceHash)
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
        json decoded_value = decode_bencoded_value(encoded_value);
        std::cout << decoded_value.dump() << std::endl;
    }
    else if (command == "info")
    {
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }
        try
        {
            /*
            retrieve the path to the torrent file
            Example: /tmp/torrents586275342/itsworking.gif.torrent
            */
            std::string filePath = argv[2];

            parse_torrent(filePath);
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
        }
    }
    else if (command == "peers")
    {
        std::string filePath = argv[2];

        try
        {
            auto [decodedTorrent, trackerURL, length, pieceLength, totalPieces, infoHash, pieceHashes] = parse_torrent_file(filePath);

            // Parse the torrent
            // Contruct GET message
            std::string peerID = "01234567890123456789";

            // parse the peers and print them
            std::vector<std::string> peerList = request_peers(trackerURL, infoHash, peerID, length);
            for (const auto &peer : peerList)
            {
                std::cout << peer << std::endl;
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
            return 1;
        }
    }
    else if (command == "handshake")
    {
        std::string filePath = argv[2];
        try
        {
            std::string peerInfo = argv[3];
            auto [peerIP, peerPort] = parse_peer_info(peerInfo);

            // read the file
            // bencode the torrent
            std::string fileContent = read_file(filePath);
            json decoded_torrent = decode_bencoded_value(fileContent);
            std::string bencoded_info = json_to_bencode(decoded_torrent["info"]);

            // calculate the info hash
            std::string infoHash = calculateInfohash(bencoded_info);
            // std::cout << binaryInfoHash << std::endl;

            // Peer ID of YOUR client
            std::string peerID = "00112233445566778899";

            /*
            1. length of the protocol string (BitTorrent protocol) which is 19 (1 byte)

            2. the string BitTorrent protocol (19 bytes)

            3. eight reserved bytes, which are all set to zero (8 bytes)

            4. sha1 infohash (20 bytes) (NOT the hexadecimal representation, which is 40 bytes long)

            5. peer id (20 bytes) (generate 20 random byte values)
            */
            Handshake handshake(hex_to_binary(infoHash), peerID);
            std::vector<char> handshakeMessage = handshake.toVector();

            // Step 1: Establish TCP connection with the peer
            int sockfd = connect_to_peer(peerIP, peerPort);

            perform_handshake(sockfd, handshakeMessage, hex_to_binary(infoHash));

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
            Handshake handshake(hex_to_binary(infoHash), peerID);
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

                perform_handshake(sockfd, handshakeMessage, hex_to_binary(infoHash));

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
/*
 *  ISA - Project: secret
 *  Michal Šlesár
 *  xslesa01
 */

#include <map>
#include <string>

#include <pcap.h>
#include <poll.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <pcap/sll.h>
#include <sys/socket.h>
#include <openssl/aes.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>

const char PROTOCOL_HASH[6] = "ISA_3";

// Header of secret protocol
struct secret_header
{
    struct icmphdr icmphdr;

    // Identifier of protocol so server can filter these packets
    char protocol_hash[6];

    // Type of packet
    int protocol_type;

    // Identifier of underlying transfer
    int transfer_id;
};

// Maximum size of whole packet can be 1500 bytes
const size_t MAX_TRANSFER_DATA = ((1500 - sizeof(struct sll_header) - sizeof(struct ip6_hdr) - sizeof(struct secret_header)) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

// Maximum size of secret_file_packet can be 1000 bytes
const size_t MAX_FILENAME_LENGTH = MAX_TRANSFER_DATA - sizeof(int);

// Packet that is sent on new file transfer
struct secret_file_packet
{
    // SECRET header
    struct secret_header header;

    // Length of file that will be transferred
    int transfer_size;

    // Name of the file that will be transferred
    char transfer_name[MAX_FILENAME_LENGTH];
};

// Maximum number of AES blocks that fit the ethernet packet
const size_t MAX_AES_BLOCKS = MAX_TRANSFER_DATA / AES_BLOCK_SIZE;

// Packet that contains transfer data
struct secret_data_packet
{
    // SECRET header
    struct secret_header header;

    // Packet payload
    unsigned char transfer_data[MAX_TRANSFER_DATA];
};

// How many seconds to wait before termination
const int INACTIVITY_TIMEOUT = 5;

// Calculate ICMP checksum
// Function was taken from https://www.geeksforgeeks.org/ping-in-c/
unsigned short checksum(void *b, int len)
{
    unsigned short *buf = (unsigned short *) b;
    unsigned int sum=0;
    unsigned short result;
  
    for(sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if(len == 1)
        sum += *(unsigned char*) buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// xslesa01
static const unsigned char aes_key[] = {
    0x78, 0x73, 0x6c, 0x65, 0x73, 0x61, 0x30, 0x31,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Sent packets counter
auto sequence = 0;

/**
 * @brief Send data to socket with address
 *
 * @param socket Socket file descriptor
 * @param pdf Poll related structure
 * @param data Data to send
 * @param transfer_id Transfer ID
 * @param address Target server address
 * @return 1 on error, 0 otherwise
 */
int send_data(int socket, pollfd *pfd, unsigned char *data, int transfer_id, addrinfo *address)
{
    struct secret_data_packet data_packet;
    memset(&data_packet, 0, sizeof(data_packet));
    data_packet.header.icmphdr.type = address->ai_family == AF_INET ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
    data_packet.header.icmphdr.un.echo.id = rand();
    data_packet.header.icmphdr.un.echo.sequence = sequence++;

    strcpy(data_packet.header.protocol_hash, PROTOCOL_HASH);
    data_packet.header.protocol_type = 2;
    data_packet.header.transfer_id = transfer_id;

    for(size_t i = 0; i < MAX_TRANSFER_DATA; i++)
        data_packet.transfer_data[i] = data[i];

    data_packet.header.icmphdr.checksum = checksum(&data_packet, sizeof(data_packet));

    poll(pfd, 1, INACTIVITY_TIMEOUT);
    auto sent = sendto(socket, &data_packet, sizeof(data_packet), 0, address->ai_addr, address->ai_addrlen);

    if(sent < 0)
        return 0;

    struct sockaddr_in r_addr;
    unsigned int addr_len = sizeof(r_addr);
    auto received = recvfrom(socket, &data_packet, sizeof(data_packet), 0, (struct sockaddr*) &r_addr, &addr_len);

    if(received < 0)
        return 0;

    return 1;
}

/**
 * @brief Client implementation
 *
 * @param address Target address
 * @param filepath File that will be sent
 * @return 1 on error, 0 otherwise
 */
int client(addrinfo *address, char *filepath)
{
    // Initialize either IPv4 or IPv6 socket
    int sockfd;
    if(address->ai_family == AF_INET)
        sockfd = socket(address->ai_family, address->ai_socktype, IPPROTO_ICMP);
    else
        sockfd = socket(address->ai_family, address->ai_socktype, IPPROTO_ICMPV6);

    if(sockfd == -1)
    {
        fprintf(stderr, "Failed to create socket\n");
        return 1;
    }

    // Prepare poll structure
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLOUT;

    // Set timeout options
    struct timeval tv_out;
    tv_out.tv_sec = INACTIVITY_TIMEOUT;
    tv_out.tv_usec = 0;

    auto optresult = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv_out, sizeof(tv_out));

    if(optresult == -1)
    {
        fprintf(stderr, "Failed to set socket options\n");
        return 1;
    }

    FILE *file = fopen(filepath, "rb");

    if(file == NULL)
    {
        fprintf(stderr, "Failed to open target file\n");
        return 1;
    }

    // Extract file name from path
    auto filename = basename(filepath);
    if(strlen(filename) > MAX_FILENAME_LENGTH)
    {
        fprintf(stdout, "Maximum size of filename can be %zu\n", MAX_FILENAME_LENGTH);
        fclose(file);
        return 1;
    } 

    // Calculate file length
    fseek(file, 0L, SEEK_END);
    auto size = ftell(file);
    fseek(file, 0L, SEEK_SET);

    // Generate transfer id
    auto transferId = rand();

    struct secret_file_packet file_packet;
    memset(&file_packet, 0, sizeof(file_packet));
    file_packet.header.icmphdr.type = address->ai_family == AF_INET ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
    file_packet.header.icmphdr.un.echo.id = rand();
    file_packet.header.icmphdr.un.echo.sequence = sequence++;
    
    strcpy(file_packet.header.protocol_hash, PROTOCOL_HASH);
    file_packet.header.transfer_id = transferId;
    file_packet.header.protocol_type = 1;

    file_packet.transfer_size = size;
    
    for(size_t i = 0; i < strlen(filename); i++)
        file_packet.transfer_name[i] = filename[i];

    file_packet.header.icmphdr.checksum = checksum(&file_packet, sizeof(file_packet));

    fprintf(stdout, "Sending file to the server... (Tranfer ID: %d)\n", transferId);

    poll(&pfd, 1, INACTIVITY_TIMEOUT);
    auto sent = sendto(sockfd, &file_packet, sizeof(file_packet), 0, address->ai_addr, address->ai_addrlen);

    if(sent < 0)
    {
        fprintf(stdout, "Could not contact the server\n");
        fclose(file);
        return 1;
    }

    struct sockaddr_in r_addr;
    unsigned int addr_len = sizeof(r_addr);
    auto received = recvfrom(sockfd, &file_packet, sizeof(file_packet), 0, (struct sockaddr*) &r_addr, &addr_len);

    if(received < 0)
    {
        fprintf(stdout, "File packet sent but reply not received\n");
        fclose(file);
        return 1;
    }

    // How many blocks of 16 bytes were parsed already
    int parsed_blocks = 0;

    // Currently parsed packet buffer
    unsigned char packetData[MAX_TRANSFER_DATA] = {0};

    // Curently parsed block buffer
    unsigned char block[AES_BLOCK_SIZE] = {0};

    long size_sent = 0;

    while (true) {
        auto bytes_read = fread(block, 1, AES_BLOCK_SIZE, file);

        fprintf(stdout, "\rProgress: %ld/%ld bytes sent", size_sent += bytes_read, size);
        fflush(stdout);

        // Encrypt block of data
        AES_KEY key;
        AES_set_encrypt_key(aes_key, 128, &key);
        AES_encrypt(block, &packetData[parsed_blocks * AES_BLOCK_SIZE], &key);
        parsed_blocks++;
        
        if(bytes_read < AES_BLOCK_SIZE)
        {
            if(!send_data(sockfd, &pfd, packetData, transferId, address))
            {
                fprintf(stdout, "\nFailed to send block of data, exiting\n");
                fclose(file);
                return 1;
            }
            break;
        }

        if(parsed_blocks == MAX_AES_BLOCKS)
        {
            if(!send_data(sockfd, &pfd, packetData, transferId, address))
            {
                fprintf(stdout, "\nFailed to send block of data, exiting\n");
                fclose(file);
                return 1;
            }
            memset(packetData, 0, MAX_TRANSFER_DATA);
            parsed_blocks = 0;
        }

        memset(block, 0, AES_BLOCK_SIZE);
    }

    fprintf(stdout, "\nFile was sent (total size: %ld bytes)\n", size);

    fclose(file);
    return 0;
}

// Transfer related information
struct transfer_info
{
    // Size of the file
    int transfer_size;

    // Number of bytes that were already received
    int transfered;

    // Time of the last received packet
    int lastUpdate;

    // File descriptor
    FILE *file;
};

// Map of all active transfers
std::map<int, transfer_info*> transfers;

/**
 * @brief Packet handler callback
 */
void packet_received(u_char */*args*/, const struct pcap_pkthdr */* header */, const u_char* packet)
{
    auto currentTime = time(NULL);

    // Remove inactive transfers from memory
    for (auto it = transfers.cbegin(), next_it = it; it != transfers.cend(); it = next_it)
    {
        ++next_it;
        auto info = it->second;
        if(info->lastUpdate + INACTIVITY_TIMEOUT < currentTime)
        {
            fprintf(stderr, "(TID: %d) Transfer terminated because of inactivity (received %d/%d bytes)\n", it->first, info->transfered, info->transfer_size);
            fclose(info->file);
            delete info;
            transfers.erase(it);
        }
    }

    auto protocol = ntohs(((struct sll_header*) packet)->sll_protocol);

    struct secret_header* secretHeader;
    if(protocol == ETHERTYPE_IP)
        secretHeader = (struct secret_header*) (packet + sizeof(struct sll_header) + sizeof(struct ip));
    else if(protocol == ETHERTYPE_IPV6)
        secretHeader = (struct secret_header*) (packet + sizeof(struct sll_header) + sizeof(struct ip6_hdr));

    // Compare protocol hash so we can filter out other ICMP messages not relevant to our app
    if(strcmp(secretHeader->protocol_hash, PROTOCOL_HASH))
        return;

    // Request for new file transfer
    if(secretHeader->protocol_type == 1)
    {
        auto fileHeader = (struct secret_file_packet*) secretHeader;

        auto file = fopen(fileHeader->transfer_name, "wb+");

        if(file == NULL)
        {
            fprintf(stderr, "(TID: %d) Could not open file with name: %s", secretHeader->transfer_id, fileHeader->transfer_name);
            return;
        }

        auto info = new transfer_info();
        info->lastUpdate = currentTime;
        info->transfer_size = fileHeader->transfer_size;
        info->file = file;

        transfers[secretHeader->transfer_id] = info;

        printf("(TID: %d) Started receiving file: %s, size: %d bytes\n", secretHeader->transfer_id, fileHeader->transfer_name, fileHeader->transfer_size);
    }
    // Data for open file transfer
    else if(secretHeader->protocol_type == 2)
    {
        auto dataHeader = (struct secret_data_packet*) secretHeader;

        // if specified transfer_id does not exist
        if(transfers.find(secretHeader->transfer_id) == transfers.end())
            return;

        auto transfer = transfers[secretHeader->transfer_id];

        unsigned char block[AES_BLOCK_SIZE] = {0};

        int parsed_blocks = 0;
        while(parsed_blocks != MAX_AES_BLOCKS && transfer->transfered < transfer->transfer_size)
        {
            AES_KEY key;
            AES_set_decrypt_key(aes_key, 128, &key);
            AES_decrypt(&dataHeader->transfer_data[parsed_blocks * AES_BLOCK_SIZE], block, &key);

            if(transfer->transfered + AES_BLOCK_SIZE >= transfer->transfer_size)
            {
                printf("(TID: %d) File received successfully\n", secretHeader->transfer_id);
                fwrite(block, 1, transfer->transfer_size - transfer->transfered, transfer->file);
                fclose(transfer->file);
                delete transfer;
                transfers.erase(secretHeader->transfer_id);
                return;
            } else {
                fwrite(block, 1, sizeof(block), transfer->file);
            }

            transfer->transfered += AES_BLOCK_SIZE;
            transfer->lastUpdate = currentTime;
            parsed_blocks++;
        }
    }
}

/**
 * @brief Server implementation
 * 
 * @return 1 on error, 0 otherwise
 */
int server()
{
    char error[PCAP_ERRBUF_SIZE];

    auto device = pcap_open_live(NULL, BUFSIZ, 0, -1, error);
    if(device == NULL)
    {
        fprintf(stderr, "Could not open 'any' interface (Reason: %s)\n", error);
        return 1;
    }

    struct bpf_program filter;
    if(pcap_compile(device, &filter, "icmp[icmptype] = icmp-echo or icmp6[icmp6type] = icmp6-echo", 0, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR)
    {
        fprintf(stderr, "Failed to compile pcap filter (Reason: %s)\n", pcap_geterr(device));
        return 1;
    }

    if(pcap_setfilter(device, &filter) == PCAP_ERROR)
    {
        fprintf(stderr, "Failed to set filter (Reason: %s)\n", pcap_geterr(device));
        return 1;
    }

    pcap_loop(device, -1, packet_received, NULL);
    return 0;
}

int main(int argc, char **argv)
{
    srand(time(0));

    char * hostname = nullptr;
    char * filepath = nullptr;
    
    // Whether the app should run in client on server mode
    bool listener = false;

    for(int i = 0; i < argc; i++)
    {
        if(!strcmp(argv[i], "-s") && i < argc) // hostname
            hostname = argv[i + 1];
        else if(!strcmp(argv[i], "-r") && i < argc) // file
            filepath = argv[i + 1];
        else if(!strcmp(argv[i], "-l")) // listener
            listener = true;
    }

    if((hostname == nullptr || filepath == nullptr) && !listener)
    {
        fprintf(stderr, "Both hostname and file must be provided in client mode\n");
        return 1;
    }

    // Server mode
    if(listener)
        return server();
    // Client mode
    else
    {
        struct addrinfo hints;
        struct addrinfo *info;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_RAW;

        if(getaddrinfo(hostname, NULL, &hints, &info) != 0)
        {
            fprintf(stderr, "Could not resolve hostname\n");
            return 1;
        }

        auto result = client(info, filepath);

        freeaddrinfo(info);

        return result;
    }
}
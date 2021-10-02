#include <map>
#include <string>

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <openssl/aes.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>

const char PROTOCOL_HASH[6] = "ISA_3";

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

// Maximum size of secret_file_packet can be 150 bytes
const size_t MAX_FILENAME_LENGTH = 150 - sizeof(secret_header) - sizeof(int);

struct secret_file_packet
{
    // SECRET header
    struct secret_header header;

    // Length of file that will be transferred
    int transfer_size;

    // Name of the file that will be transferred
    char transfer_name[MAX_FILENAME_LENGTH];
};

// Maximum size of secret_data_packet can be 150 bytes
const size_t MAX_TRANSFER_DATA = ((150 - sizeof(secret_header)) / AES_BLOCK_SIZE) * 16;

const size_t MAX_AES_BLOCKS = MAX_TRANSFER_DATA / AES_BLOCK_SIZE;

struct secret_data_packet
{
    // SECRET header
    struct secret_header header;

    // Packet payload
    unsigned char transfer_data[MAX_TRANSFER_DATA];
};

// Calculating the Check Sum
unsigned short checksum(void *b, int len)
{    
	unsigned short *buf = (unsigned short *) b;
    unsigned int sum=0;
    unsigned short result;
  
    for(sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if(len == 1 )
        sum += *(unsigned char*)buf;

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

int send_data(int socket, unsigned char *data, int transfer_id, sockaddr_in address)
{
    struct secret_data_packet data_packet;
    bzero(&data_packet, sizeof(data_packet));
    data_packet.header.icmphdr.type = ICMP_ECHO;
    data_packet.header.icmphdr.un.echo.id = rand();
    data_packet.header.icmphdr.un.echo.sequence = rand();

    strcpy(data_packet.header.protocol_hash, PROTOCOL_HASH);
    data_packet.header.protocol_type = 2;
    data_packet.header.transfer_id = transfer_id;

    for(int i = 0; i < MAX_TRANSFER_DATA; i++)
        data_packet.transfer_data[i] = data[i];

    data_packet.header.icmphdr.checksum = checksum(&data_packet, sizeof(data_packet));

    auto sent = sendto(socket, &data_packet, sizeof(data_packet), 0, (struct sockaddr*) &address, sizeof(address));

    if(sent < 0)
        return 0;

    struct sockaddr_in r_addr;
    unsigned int addr_len = sizeof(r_addr);
    auto received = recvfrom(socket, &data_packet, sizeof(data_packet), 0, (struct sockaddr*) &r_addr, &addr_len);

    if(received < 0)
        return 0;

    return 1;
}

int client(in_addr_t address, char *filename)
{
    struct sockaddr_in servaddr;
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = address;
    servaddr.sin_port = 0;
	memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

    auto sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    int ttl_val = 10;
    struct timeval tv_out;
    tv_out.tv_sec = 1;
    tv_out.tv_usec = 0;

    setsockopt(sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out));

    // Calculate file length
    FILE *file = fopen(filename, "rb");
    fseek(file, 0L, SEEK_END);
    auto size = ftell(file);
    fseek(file, 0L, SEEK_SET);

    struct secret_file_packet file_packet;
    bzero(&file_packet, sizeof(file_packet));
    file_packet.header.icmphdr.type = ICMP_ECHO;
    file_packet.header.icmphdr.un.echo.id = rand();
    file_packet.header.icmphdr.un.echo.sequence = rand();

    auto id = rand();
    
    strcpy(file_packet.header.protocol_hash, PROTOCOL_HASH);
    file_packet.header.transfer_id = id;
    file_packet.header.protocol_type = 1;

    file_packet.transfer_size = size;
    
    for(auto i = 0; i < strlen(filename); i++)
        file_packet.transfer_name[i] = filename[i];

    file_packet.header.icmphdr.checksum = checksum(&file_packet, sizeof(file_packet));

    printf("Sending file to the server...\n");

    auto sent = sendto(sockfd, &file_packet, sizeof(file_packet), 0, (struct sockaddr*) &servaddr, sizeof(servaddr));

    if(sent < 0)
    {
        printf("Could not contact server\n");
        fclose(file);
        return 1;
    }

    struct sockaddr_in r_addr;
    unsigned int addr_len = sizeof(r_addr);
    auto received = recvfrom(sockfd, &file_packet, sizeof(file_packet), 0, (struct sockaddr*) &r_addr, &addr_len);

    if(received < 0)
    {
        printf("File packet sent but reply not received\n");
        fclose(file);
        return 1;
    }

    int bytes_read, bytes_written;

    int parsed_blocks = 0;

    unsigned char packetData[MAX_TRANSFER_DATA] = {0};

    unsigned char block[AES_BLOCK_SIZE] = {0};

    while (true) {
        bytes_read = fread(block, 1, AES_BLOCK_SIZE, file);

        AES_KEY key;
        AES_set_encrypt_key(aes_key, 128, &key);
        AES_encrypt(block, &packetData[parsed_blocks * AES_BLOCK_SIZE], &key);
        parsed_blocks++;
        
        if(bytes_read < AES_BLOCK_SIZE)
        {
            if(!send_data(sockfd, packetData, id, servaddr))
            {
                printf("Failed to send block of data, exiting\n");
                fclose(file);
                return 1;
            }
            break;
        }

        if(parsed_blocks == MAX_AES_BLOCKS)
        {
            if(!send_data(sockfd, packetData, id, servaddr))
            {
                printf("Failed to send block of data, exiting\n");
                fclose(file);
                return 1;
            }
            memset(packetData, 0, MAX_TRANSFER_DATA);
            parsed_blocks = 0;
        }
    }

    printf("File was sent (total size: %d bytes)\n", size);

    fclose(file);
    return 0;
}

struct transfer_info
{
    int transfer_size;

    int transfered;

    FILE *file;
};

std::map<int, transfer_info*> transfers;

void packet_received(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    auto ethernetHeader = (struct ether_header*) packet;
    if (ntohs(ethernetHeader->ether_type) != ETHERTYPE_IP)
        return;
    
    auto ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

    if (ipHeader->ip_p != IPPROTO_ICMP)
        return;

    auto secretHeader = (struct secret_header*) (packet + sizeof(struct ether_header) + sizeof(struct ip));

    if(strcmp(secretHeader->protocol_hash, PROTOCOL_HASH))
        return;

    if(secretHeader->protocol_type == 1)
    {
        auto fileHeader = (struct secret_file_packet*) (packet + sizeof(struct ether_header) + sizeof(struct ip));

        auto info = new transfer_info();
        info->file = fopen(std::to_string(secretHeader->transfer_id).c_str(), "wb");
        info->transfer_size = fileHeader->transfer_size;
        transfers[secretHeader->transfer_id] = info;

        printf("(TID: %d) Started receiving file: %s, size: %d bytes\n", secretHeader->transfer_id, fileHeader->transfer_name, fileHeader->transfer_size);
    }
    else if(secretHeader->protocol_type == 2)
    {
        auto dataHeader = (struct secret_data_packet*) (packet + sizeof(struct ether_header) + sizeof(struct ip));

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

            if(transfer->transfered + 16 > transfer->transfer_size)
            {
                printf("(TID: %d) File received successfully\n", secretHeader->transfer_id);
                fwrite(block, 1, transfer->transfer_size - transfer->transfered, transfer->file);
                fclose(transfer->file);
                delete transfer;
                transfers.erase(secretHeader->transfer_id);
            } else {
                fwrite(block, 1, sizeof(block), transfer->file);
            }

            transfer->transfered += AES_BLOCK_SIZE;
            parsed_blocks++;
        }
    }
}

int server()
{
    char error[PCAP_ERRBUF_SIZE];

    pcap_if_t *interfaces;
    pcap_findalldevs(&interfaces, error);
    auto device = pcap_open_live(interfaces[0].name, BUFSIZ, 0, -1, error);

    struct bpf_program filter;
    bpf_u_int32 ip;

    pcap_compile(device, &filter, "icmp[icmptype] = 8", 0, ip);
    pcap_setfilter(device, &filter);

    pcap_loop(device, 20, packet_received, NULL);
    return 0;
}

int main(int argc, char **argv)
{
    srand(time(0));

    char * hostname = nullptr;
    char * filename = nullptr;
    bool listener = false;

    for(int i = 0; i < argc; i++)
    {
        if(!strcmp(argv[i], "-s") && i < argc) // hostname
            hostname = argv[i + 1];
        else if(!strcmp(argv[i], "-r") && i < argc) // file
            filename = argv[i + 1];
        else if(!strcmp(argv[i], "-l")) // listener
            listener = true;
    }

    if((hostname == nullptr || filename == nullptr) && !listener)
    {
        printf("Both hostname and file must be provided in client mode\n");
        return 1;
    }

    if(listener)
        return server();
    else
    {
        auto address = inet_addr(hostname);
        return client(address, filename);
    }
}
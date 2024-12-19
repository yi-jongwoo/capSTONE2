#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <ns3/core-module.h>
#include <ns3/internet-module.h>
#include <ns3/network-module.h>
#include <ns3/ipv4-address.h>

using namespace ns3;
using namespace std;

typedef vector<uint8_t> bytes;

struct ClientMemory {
    Ipv4Address my_ip;
    uint16_t my_udp_port;
    uint16_t my_tcp_port;
    Ipv4Address parent_ip; // Parent node's IP address
    uint16_t parent_tcp_port; // Parent node's TCP port
    vector<bytes> buffer;

    uint64_t uploaded_bytes = 0;
    uint64_t downloaded_bytes = 0;
    int integrity_failures = 0;
    int freerider_stack = 0;
    vector<bool> chunks; // Each client's chunk ownership
};

const int peer_cnt = 8;
const int num_of_chunks = 100;
ClientMemory arr[1 + peer_cnt];

void InitializeClientMemory(int index, Ipv4Address ip, uint16_t udp_port, uint16_t tcp_port) {
    arr[index].my_ip = ip;
    arr[index].my_udp_port = udp_port;
    arr[index].my_tcp_port = tcp_port;
    arr[index].parent_ip = Ipv4Address("0.0.0.0"); // Initialize as unknown
    arr[index].parent_tcp_port = 0;
    arr[index].buffer.clear();
    arr[index].uploaded_bytes = 0;
    arr[index].downloaded_bytes = 0;
    arr[index].integrity_failures = 0;
    arr[index].freerider_stack = 0;
    arr[index].chunks.resize(num_of_chunks, false); // Initialize chunk ownership
}

void UpdateMetrics(int index, uint64_t uploaded, uint64_t downloaded, bool integrityFailed = false) {
    arr[index].uploaded_bytes += uploaded;
    arr[index].downloaded_bytes += downloaded;
    if (integrityFailed) {
        arr[index].integrity_failures++;
    }
}

void RequestChunkFromParent(int index, uint32_t chunkNumber) {
    if (arr[index].parent_ip == Ipv4Address("0.0.0.0") || arr[index].parent_tcp_port == 0) {
        cerr << "Parent node information is not set for client " << index << ".\n";
        return;
    }

    // Prepare a buffer for the payload
    uint8_t buffer[1029];

    // First byte: sender type (3 for child)
    buffer[0] = 3;

    // Next 4 bytes: chunk number (network byte order)
    uint32_t chunkNetworkOrder = htonl(chunkNumber);
    memcpy(buffer + 1, &chunkNetworkOrder, sizeof(chunkNetworkOrder));

    // Remaining 1024 bytes: payload (empty in this case, could add additional data if needed)
    memset(buffer + 5, 0, 1024);

    // Send the request via TCP
    string payload(reinterpret_cast<char*>(buffer), sizeof(buffer));
    SendTcpPacket(index, arr[index].parent_ip, arr[index].parent_tcp_port, payload);

    arr[index].freerider_stack++;
}

void check_has_chunk(int i, int chunk_id) {
    if (arr[i].chunks[chunk_id]) {
        // Node already has the chunk, no action needed
    } else {
        // Node does not have the chunk, request it from parent
        RequestChunkFromParent(i, chunk_id);
    }
}

void DetectFreeridersAndDelete() {
    for (int i = 1; i <= peer_cnt; i++) {
        double ratio = arr[i].downloaded_bytes > 0
                           ? (double)arr[i].uploaded_bytes / arr[i].downloaded_bytes
                           : 0.0;

        if (ratio < 0.1 || arr[i].freerider_stack > 5) {
            deletePeerQuery(arr[i].my_ip.ToString());
            InitializeClientMemory(i, Ipv4Address("0.0.0.0"), 0, 0);
        }
    }
}

void ProcessDataIntegrityResult(int index, const string& content, uint32_t chunkNumber, int parentIndex) {
    bool integrityFailed = (content != "valid");
    UpdateMetrics(index, 0, 0, integrityFailed);
    if (!integrityFailed) {
        arr[index].chunks[chunkNumber] = true; // Mark chunk as valid
    } else {
        RequestChunkFromParent(index, chunkNumber);
    }
    DetectFreeridersAndDelete();
}

void ProcessReceivedData(uint8_t senderType, uint32_t chunkNumber, const string& content, int index, int parentIndex) {
    switch (senderType) {
        case 0:
            ProcessDataIntegrityResult(index, content, chunkNumber, parentIndex);
            break;
        case 1:
            arr[index].chunks[chunkNumber] = true; // Assume chunk is received correctly
            break;
        case 2:
            // Handle integrity check results
            break;
        case 3:
            // Handle retransmission requests
            break;
        default:
            cerr << "Unknown sender type: " << senderType << "\n";
            break;
    }
}

void HandleReceivedTcpData(Ptr<Socket> socket, int index) {
    Ptr<Packet> packet = socket->Recv();
    uint8_t buffer[1029];
    packet->CopyData(buffer, sizeof(buffer));

    uint8_t senderType = buffer[0];
    uint32_t chunkNumber;
    memcpy(&chunkNumber, buffer + 1, sizeof(chunkNumber));
    chunkNumber = ntohl(chunkNumber);
    string content(reinterpret_cast<char*>(buffer + 5), 1024);

    int parentIndex = index - 1; // Example: Determine parentIndex
    ProcessReceivedData(senderType, chunkNumber, content, index, parentIndex);
}

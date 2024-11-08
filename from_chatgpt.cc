#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"
#include "ns3/random-variable-stream.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("UdpOverTcpExample");

// UDP 정보 수신 후 난수 데이터를 전송하는 콜백 함수
void ReceiveTcpAndSendUdp(Ptr<Socket> udpSocket, Ptr<UniformRandomVariable> randomData, Ptr<Socket> tcpSocket) {
    Address remoteAddress;
    Ptr<Packet> packet = tcpSocket->RecvFrom(remoteAddress);
    
    if (InetSocketAddress::IsMatchingType(remoteAddress)) {
        InetSocketAddress inetSockAddr = InetSocketAddress::ConvertFrom(remoteAddress);
        Ipv4Address udpAddr = inetSockAddr.GetIpv4();
        uint16_t udpPort = inetSockAddr.GetPort();
        
        // 난수 데이터 전송
        uint8_t data[1024];
        for (uint32_t i = 0; i < 1024; ++i) {
            data[i] = static_cast<uint8_t>(randomData->GetValue(0, 255));
        }
        Ptr<Packet> udpPacket = Create<Packet>(data, 1024);
        udpSocket->Connect(InetSocketAddress(udpAddr, udpPort));
        udpSocket->Send(udpPacket);
    }
}

// UDP 수신 후 로깅을 위한 콜백 함수
void LogReceivedUdpPacket(Ptr<const Packet> packet) {
    NS_LOG_UNCOND("Node 2 received UDP packet of size " << packet->GetSize());
}

int main(int argc, char *argv[]) {
    // 노드 생성
    NodeContainer nodes;
    nodes.Create(4);

    // CSMA 설정
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
    csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(6560)));

    // 네트워크 장치 설치
    NetDeviceContainer devices = csma.Install(nodes);

    // 인터넷 스택 설치
    InternetStackHelper internet;
    internet.Install(nodes);

    // IP 주소 할당
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // UDP 서버 설정: 노드 2에서 수신
    uint16_t udpPort = 8080;
    UdpServerHelper udpServer(udpPort);
    ApplicationContainer udpServerApp = udpServer.Install(nodes.Get(2));
    udpServerApp.Start(Seconds(1.0));
    udpServerApp.Stop(Seconds(20.0));

    // TCP 서버 설정: 노드 1에서 수신
    uint16_t tcpPort = 8081;
    Address tcpLocalAddress(InetSocketAddress(Ipv4Address::GetAny(), tcpPort));
    PacketSinkHelper tcpServer("ns3::TcpSocketFactory", tcpLocalAddress);
    ApplicationContainer tcpServerApp = tcpServer.Install(nodes.Get(1));
    tcpServerApp.Start(Seconds(1.0));
    tcpServerApp.Stop(Seconds(20.0));

    // TCP 클라이언트 설정: 노드 0에서 송신
    OnOffHelper tcpClient("ns3::TcpSocketFactory", InetSocketAddress(interfaces.GetAddress(1), tcpPort));
    tcpClient.SetAttribute("DataRate", StringValue("5Mbps"));
    tcpClient.SetAttribute("PacketSize", UintegerValue(1024));
    tcpClient.SetAttribute("MaxBytes", UintegerValue(1024)); // 한번 전송하고 멈춤
    ApplicationContainer tcpClientApp = tcpClient.Install(nodes.Get(0));
    tcpClientApp.Start(Seconds(3.0));
    tcpClientApp.Stop(Seconds(20.0));

    // 노드 1에서 UDP 정보를 수신하고 노드 2로 데이터 전송
    Ptr<UniformRandomVariable> randomData = CreateObject<UniformRandomVariable>();
    Ptr<UdpSocketFactory> udpFactory = CreateObject<UdpSocketFactory>();
    Ptr<Socket> udpSocket = udpFactory->CreateSocket(nodes.Get(1));
    udpSocket->SetAllowBroadcast(true);
    udpSocket->Bind();
    
    Ptr<Socket> tcpSocket = tcpServerApp.Get(0)->GetObject<PacketSink>()->GetSocket();
    tcpSocket->SetRecvCallback(MakeBoundCallback(&ReceiveTcpAndSendUdp, udpSocket, randomData));

    // UDP 서버에서 수신된 데이터를 로깅
    udpServerApp.Get(0)->GetObject<UdpServer>()->TraceConnectWithoutContext("Rx", MakeCallback(&LogReceivedUdpPacket));

    // 시뮬레이션 실행
    Simulator::Run();
    Simulator::Destroy();

    return 0;
}

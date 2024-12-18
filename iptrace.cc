#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

void PacketReceived(Ptr<const Packet> packet, const Ipv4Header &header, Ptr<const NetDevice> device)
{
    // IP 패킷 송수신 정보 출력
    std::cout << "Received packet: " << packet->GetSize() << " bytes, "
              << "From: " << header.GetSource() << ", "
              << "To: " << header.GetDestination() << std::endl;
}

void PacketSent(Ptr<const Packet> packet, const Ipv4Header &header, Ptr<const NetDevice> device)
{
    // IP 패킷 송수신 정보 출력
    std::cout << "Sent packet: " << packet->GetSize() << " bytes, "
              << "From: " << header.GetSource() << ", "
              << "To: " << header.GetDestination() << std::endl;
}

int main()
{
    // 노드와 네트워크 스택 설정
    NodeContainer nodes;
    nodes.Create(2);
    InternetStackHelper internet;
    internet.Install(nodes);

    // IP 주소 할당
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    ipv4.Assign(NetDeviceContainer(nodes.Get(0)->GetDevice(0), nodes.Get(1)->GetDevice(0)));

    // 트레이스 설정
    Ptr<Ipv4> ipv4_0 = nodes.Get(0)->GetObject<Ipv4>();
    Ptr<Ipv4> ipv4_1 = nodes.Get(1)->GetObject<Ipv4>();
    
    ipv4_0->TraceConnectWithoutContext("PacketSend", MakeCallback(&PacketSent));
    ipv4_1->TraceConnectWithoutContext("PacketReceive", MakeCallback(&PacketReceived));

    // 애플리케이션 설치 및 시뮬레이션 시작
    UdpEchoServerHelper echoServer(9);
    ApplicationContainer serverApp = echoServer.Install(nodes.Get(1));
    serverApp.Start(Seconds(1.0));
    serverApp.Stop(Seconds(10.0));

    UdpEchoClientHelper echoClient(Ipv4Address("10.1.1.2"), 9);
    echoClient.SetAttribute("MaxPackets", UintegerValue(1));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    echoClient.SetAttribute("PacketSize", UintegerValue(1024));
    ApplicationContainer clientApp = echoClient.Install(nodes.Get(0));
    clientApp.Start(Seconds(2.0));
    clientApp.Stop(Seconds(10.0));

    Simulator::Run();
    Simulator::Destroy();

    return 0;
}

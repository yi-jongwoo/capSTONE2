#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"
#include "ns3/random-variable-stream.h"
#include <string>
#include <iostream>

using namespace ns3;
typedef std::string bytes;
using namespace std;
NS_LOG_COMPONENT_DEFINE("out1");
void tcp_peer(Ptr<Socket> socket){
	NS_LOG_INFO("TCP FAIL 15");
	exit(99);
}
void tcp_succ(Ptr<Socket> socket){
	NS_LOG_INFO("TCP CONNECTED 19");
	bytes payload = "abcd";
	Ptr<Packet> packet = Create<Packet>
		((uint8_t*)payload.c_str(),payload.size());
	socket->Send(packet);
}
void tcp_fail(Ptr<Socket> socket){
	NS_LOG_INFO("TCP FAIL");
	exit(99);
}
NodeContainer nodes;
Ipv4Address private_memory[100];

struct socketFunctor{
	int id;
	function<void(Ptr<Socket>,int)> ff;
	socketFunctor(int i,function<void(Ptr<Socket>,int)> f)
		:id(i),ff(f){}
	void operator()(Ptr<Socket> socket)const{
		ff(socket,id);
	}
};
void NewTcpSocket(Ptr<Node> node, Ipv4Address sip, uint16_t port,
	socketFunctor ff){
	Ptr<Socket> socket = Socket::CreateSocket
		(node,TcpSocketFactory::GetTypeId());
	InetSocketAddress tcpAddr = InetSocketAddress(sip,port);
	socket->SetConnectCallback(
		MakeCallback(&socketFunctor::operator(),&ff),
		MakeCallback(&tcp_fail)
	);
	socket->Connect(tcpAddr);
}
void NewUdpSocket(Ptr<Node> node, Ipv4Address sip, uint16_t port,
	socketFunctor ff){
	Ptr<Socket> socket = Socket::CreateSocket
		(node,UdpSocketFactory::GetTypeId());
	InetSocketAddress udpAddr = InetSocketAddress(sip,port);
	socket->SetConnectCallback(
		MakeCallback(&socketFunctor::operator(),&ff),
		MakeCallback(&tcp_fail)
	);
	socket->Connect(udpAddr);
}


void server_init(Ptr<Node> node, Ipv4Address sip, uint16_t port){
	Ptr<Socket> socket = Socket::CreateSocket
		(node,TcpSocketFactory::GetTypeId());
	InetSocketAddress tcpAddr = InetSocketAddress(sip,port);
	socket->SetConnectCallback(
		MakeCallback(tcp_succ),
		MakeCallback(tcp_fail)
	);
	socket->Connect(tcpAddr);
}
//Ptr<Socket> socket, , const Address & address
void node1recv( Ptr<const Packet> packet, const Address & address){
	//uint8_t tmp[1024]={0};
	//packet->CopyData(tmp,packet->GetSize());
	//NS_LOG_INFO(tmp);
	socketFunctor sf(1,[](Ptr<Socket>socket,int i){
		NS_LOG_INFO("TCP CONNECTED 81");
		bytes payload = "efgh";
		Ptr<Packet> packet = Create<Packet>
			((uint8_t*)payload.c_str(),payload.size());
		socket->Send(packet);
	});
	NewUdpSocket( nodes.Get(1), private_memory[1], 8080,sf);
}
void node2recv( Ptr<Socket> socket){
	Ptr<Packet> packet;
	Address address;
	while((packet=socket->RecvFrom(address))){
		uint8_t tmp[1024]={0};
		packet->CopyData(tmp,packet->GetSize());
		NS_LOG_INFO(tmp);
	}
}

void setting(Ipv4InterfaceContainer ipif){
/*
	// UDP 서버 설정: 노드 2에서 수신
	uint16_t udpPort = 8080;
	UdpServerHelper udpServer(udpPort);
	ApplicationContainer udpServerApp = udpServer.Install(nodes.Get(2));
	udpServerApp.Start(Seconds(1.0));
	udpServerApp.Stop(Seconds(20.0));
*/
	// TCP 서버 설정: 노드 1에서 수신
	uint16_t tcpPort = 8081;
	Address tcpLocalAddress(InetSocketAddress(Ipv4Address::GetAny(), tcpPort));
	PacketSinkHelper tcpServer("ns3::TcpSocketFactory", tcpLocalAddress);
	ApplicationContainer tcpServerApp = tcpServer.Install(nodes.Get(1));
	tcpServerApp.Start(Seconds(1.0));
	tcpServerApp.Stop(Seconds(20.0));
	
	
	private_memory[1] = ipif.GetAddress(2);
	// NODE 1 practice
	Ptr<PacketSink> sink =tcpServerApp.Get(0)->GetObject<PacketSink>();
	sink->TraceConnectWithoutContext("Rx",
		MakeCallback(&node1recv));
	
	Ptr<Socket> udp=Socket::CreateSocket(nodes.Get(2),
		UdpSocketFactory::GetTypeId());
	udp->Bind(InetSocketAddress(Ipv4Address::GetAny(), 8080));
	udp->SetRecvCallback(MakeCallback(&node2recv));
	
	Simulator::Schedule(Seconds(2.0),&server_init,
		nodes.Get(0),ipif.GetAddress(1),tcpPort);
}

int main(int argc, char *argv[]) {
	//LogCompenentEnable("out1",LOG_LEVEL_ALL);
	
	// 노드 생성
	//NodeContainer nodes;
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
	
	setting(interfaces); // dynamic?	
	
	// let's go
	Simulator::Run();
	Simulator::Destroy();
}

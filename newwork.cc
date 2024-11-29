#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"
#include "ns3/random-variable-stream.h"
#include <string>
#include <vector>
#include <array>
#include <utility>
#include <map>
//#include <iostream>

const int peer_cnt = 10; // # of peer
const double t_begin = 100; // simulation begin time
const double t_end = 200; // simulation end time

using namespace ns3;
typedef std::string bytes;
typedef unsigned __int64_t ull;
using namespace std;
NS_LOG_COMPONENT_DEFINE("out1");
NodeContainer nodes;

void tcp_fail(Ptr<Socket> socket){
	NS_LOG_INFO("TCP FAIL");
	exit(99); // what can i do?
}
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
	socket->Close();
}
void SendTcpPacket(int i, Ipv4Address sip, uint16_t port, string payload){
	NewTcpSocket(nodes.Get(i),sip,port,socketFunctor(i,[=](Ptr<Socket>socket,int)){
		Ptr<Packet> packet = Create<Packet>
			((uint8_t*)payload.c_str(),payload.size());
		socket->Send(packet);
	});
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
void SendUdpPacket(int i, Ipv4Address sip, uint16_t port, string payload){
	NewUdpSocket(nodes.Get(i),sip,port,socketFunctor(i,[=](Ptr<Socket>socket,int)){
		Ptr<Packet> packet = Create<Packet>
			((uint8_t*)payload.c_str(),payload.size());
		socket->Send(packet);
	});
}

pair<Ipv4Address,uint16_t> fromull(ull v){
	return {Ipv4Address(v & 0xffffffff),v >> 32 };
}
ull toull(Ipv4Address ip,uint16_t port){
	return ip.Get() | ull(port)<<32;
}

class LinkProfile{
	std::array<ull,8> addr;
public:
	LinkProfile(){}
	LinkProfile(const bytes& dat){ // decode from bytes
		memcpy(&addr,&dat[0],sizeof addr);
	}
	bytes encode(){
		bytes dat(sizeof addr);
		memcpy(&dat[0],&addr,sizeof addr);
		return dat;
	}
	ull operator[](int i){
		return addr[i];
	}
};

namespace Server{
	typedef ull addr_t; // addr_t = UDP/IP addr + port -> let be 8byte
	typedef ull tcp_t;
	
}

struct ClientMemory{
	Ipv4Address my_ip;
	uint16_t my_udp_port;
	uint16_t my_tcp_port;
	vector<bytes> buffer;
	LinkProfile profile;
};
ClientMemory arr[1+peer_cnt];

void server_tcp_recv( Ptr<const Packet> packet, const Address & address){
	switch(payload[0]){
	case 0: // peer wants itself to be added
		addPeerQuery(payload.substr(1));
		break;
	case 1: // peer wants peer(?) to be deleted
		deletePeerQuery(payload.substr(1));
		break;
	case 2: // exceptional security issue 
		break;
	default:
		assert(false);// wrong query identifier
	}
}
void client_tcp_recv( Ptr<const Packet> packet, const Address & address){
	
}
void server_udp_recv( Ptr<Socket> socket){
	Ptr<Packet> packet;
	Address address;
	while((packet=socket->RecvFrom(address))){
		uint8_t tmp[1024]={0};
		packet->CopyData(tmp,packet->GetSize());
		NS_LOG_INFO(tmp);
	}
}
void client_udp_recv( Ptr<Socket> socket){
	Ptr<Packet> packet;
	Address address;
	while((packet=socket->RecvFrom(address))){
		uint8_t tmp[1024]={0};
		packet->CopyData(tmp,packet->GetSize());
		NS_LOG_INFO(tmp);
	}
}
void client_init(int i, Ipv4Address sip, uint16_t port){
	ull v=toull(arr[i].my_ip,arr[i].my_udp_port);
	NewTcpSocket(nodes.Get(i),sip,port,socketFunctor(i,[=](Ptr<Socket>socket,int)){
		string payload(9,char(0));
		payload[0] = 0;
		*(ull*)payload[1] = v;
		Ptr<Packet> packet = Create<Packet>
			((uint8_t*)payload.c_str(),payload.size());
		socket->Send(packet);
	});
}

void setting(Ipv4InterfaceContainer ipif){
	uint16_t udpPort=8080, tcpPort = 8081; // tcp port of server ....and also client now
	
	ApplicationContainer tcpServerApp[peer_cnt+1];
	for(int i=0;i<=peer_cnt;i++){
		arr[i].my_ip = ipif.GetAddress(i);
		arr[i].my_tcp_port = tcpPort;
		arr[i].my_udp_port = udpPort;
		Address tcpLocalAddress(InetSocketAddress(Ipv4Address::GetAny(), arr[i].my_tcp_port));
		PacketSinkHelper tcpServer("ns3::TcpSocketFactory", tcpLocalAddress);
		tcpServerApp[i] = tcpServer.Install(nodes.Get(i));
		tcpServerApp[i].Start(Seconds(t_begin - 0.1));
		tcpServerApp[i].Stop(Seconds(t_end));
		Ptr<PacketSink> sink =tcpServerApp[i].Get(0)->GetObject<PacketSink>();
		sink->TraceConnectWithoutContext("Rx",MakeCallback(
			i ? &client_tcp_recv : &server_tcp_recv
		));
		
		Ptr<Socket> udp=Socket::CreateSocket(nodes.Get(i),
			UdpSocketFactory::GetTypeId());
		udp->Bind(InetSocketAddress(Ipv4Address::GetAny(), arr[i].my_udp_port));
		udp->SetRecvCallback(MakeCallback(
			i ? &client_udp_recv : &server_udp_recv
		));
		if(i){
			Simulator::Schedule(Seconds(t_begin + i),&cli_init,
				i,ipif.GetAddress(0),tcpPort, m);
		}
		else{
			
		}
	}
	
}

int main(int argc, char *argv[]) {
	//LogCompenentEnable("out1",LOG_LEVEL_ALL);
	
	// 노드 생성
	//NodeContainer nodes;
	nodes.Create(1 + peer_cnt);
	
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
	
	setting(interfaces); // here we modify	
	
	// let's go
	Simulator::Run();
	Simulator::Destroy();
}

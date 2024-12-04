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
typedef uint64_t ull;
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
	NewTcpSocket(nodes.Get(i),sip,port,socketFunctor(i,[=](Ptr<Socket>socket,int){
		Ptr<Packet> packet = Create<Packet>
			((uint8_t*)payload.c_str(),payload.size());
		socket->Send(packet);
	}));
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
	NewUdpSocket(nodes.Get(i),sip,port,socketFunctor(i,[=](Ptr<Socket>socket,int){
		Ptr<Packet> packet = Create<Packet>
			((uint8_t*)payload.c_str(),payload.size());
		socket->Send(packet);
	}));
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
		bytes dat(sizeof addr,char(0));
		memcpy(&dat[0],&addr,sizeof addr);
		return dat;
	}
	ull& operator[](int i){
		return addr[i];
	}
};

namespace Client{
	// by stonejjun03
}

namespace Server{
	typedef ull addr_t; // addr_t = UDP/IP addr + port -> let be 8byte
	typedef ull tcp_t;
	class PeerTree{
		std::vector<std::pair<tcp_t,addr_t>> arr;
		std::map<tcp_t,int> addr_idx;
		LinkProfile extProfile(int i){
			LinkProfile p; // let 0.0.0.0 means nowhere 
			p[0]=arr[i/4].second;
			p[1]=arr[i/2].second;
			if(i*2<ssize(arr))p[2]=arr[i*2].second;
			if(i*2+1<ssize(arr))p[3]=arr[i*2+1].second;
			if(i*4<ssize(arr))p[4]=arr[i*4].second;
			if(i*4+1<ssize(arr))p[5]=arr[i*4+1].second;
			if(i*4+2<ssize(arr))p[6]=arr[i*4+2].second;
			if(i*4+3<ssize(arr))p[7]=arr[i*4+3].second;
			return p;
		}
	public:
		PeerTree():arr(1){} // let [0] be data source ( central server )
		void init(tcp_t t,tcp_t u){
			arr[0]={t,u}; //arr[0] should never changes..?
			addr_idx[t]=0;
		}
		std::vector<std::pair<tcp_t,LinkProfile>> addPeer(tcp_t t,addr_t u){
			std::vector<std::pair<tcp_t,LinkProfile>> res;
			int i=ssize(arr);
			arr.emplace_back(t,u);
			addr_idx[t]=i;
			if(i/4)res.emplace_back(arr[i/4].first,extProfile(i/4)); // pp
			if(i/2)res.emplace_back(arr[i/2].first,extProfile(i/2)); // p
			res.emplace_back(arr[i].first,extProfile(i));
			return res;
		}
		std::vector<std::pair<tcp_t,LinkProfile>> deletePeer(int i){
			std::vector<std::pair<tcp_t,LinkProfile>> res;
			addr_idx.erase(arr[i].first);
			arr[i]=arr.back(); arr.pop_back();
			addr_idx[arr[i].first]=i;
			if(i/4)res.emplace_back(arr[i/4].first,extProfile(i/4)); // pp
			if(i/2)res.emplace_back(arr[i/2].first,extProfile(i/2)); // p
			res.emplace_back(arr[i].first,extProfile(i));
			if(i*2<ssize(arr))res.emplace_back(arr[i*2].first,extProfile(i*2));
			if(i*2+1<ssize(arr))res.emplace_back(arr[i*2+1].first,extProfile(i*2+1));
			if(i*4<ssize(arr))res.emplace_back(arr[i*4].first,extProfile(i*4));
			if(i*4+1<ssize(arr))res.emplace_back(arr[i*4+1].first,extProfile(i*4+1));
			if(i*4+2<ssize(arr))res.emplace_back(arr[i*4+2].first,extProfile(i*4+2));
			if(i*4+3<ssize(arr))res.emplace_back(arr[i*4+3].first,extProfile(i*4+3));
			int j=ssize(arr);
			if(j/4)res.emplace_back(arr[j/4].first,extProfile(j/4)); // pp
			if(j/2)res.emplace_back(arr[j/2].first,extProfile(j/2)); // p
			return res;
		}
	};
	
	PeerTree server_address;

	void addPeerQuery(const std::string_view& payload){ // [ itself addr tcp|udp ]
		ull addr[2];
		memcpy(&addr,&payload[0],sizeof addr);
		// call addPeer
		auto res=server_address.addPeer(addr[0],addr[1]);
		for(auto[tcpa,profile]:res){
			auto[addr,port]=fromull(tcpa);
			SendTcpPacket(0, addr, port, profile.encode());
		}
	}
	void deletePeerQuery(const std::string_view& payload){ // [ itself addr ]
		ull addr[2];
		//memcpy(&addr,&payload[0],sizeof addr);
		
		//auto res=server_address.deletePeer(addr[0],addr[1]);
	}
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
	string payload(packet->GetSize(),char(0));
	packet->CopyData((uint8_t*)&payload[0],packet->GetSize());
	
	switch(payload[0]){
	case 0: // peer wants itself to be added
		Server::addPeerQuery(payload.substr(1));
		break;
	case 1: // peer wants peer(?) to be deleted
		Server::deletePeerQuery(payload.substr(1));
		break;
	case 2: // exceptional security issue 
		break;
	default:
		;// assert(false);// wrong query identifier
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
	ull t=toull(arr[i].my_ip,arr[i].my_tcp_port);
	ull v=toull(arr[i].my_ip,arr[i].my_udp_port);
	NewTcpSocket(nodes.Get(i),sip,port,socketFunctor(i,[=](Ptr<Socket>socket,int){
		string payload(17,char(0));
		payload[0] = 0;
		*(ull*)payload[1] = t;
		*(ull*)payload[9] = v;
		Ptr<Packet> packet = Create<Packet>
			((uint8_t*)payload.c_str(),payload.size());
		socket->Send(packet);
	}));
}

void setting(Ipv4InterfaceContainer ipif){
	uint16_t udpPort=8080, tcpPort = 8081; // tcp port of server ....and also of client now
	
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
			Simulator::Schedule(Seconds(t_begin + i),&client_init,
				i,ipif.GetAddress(0),tcpPort);
		}
		else{
			// does server need initializing
		}
	}
	
}

int main(int argc, char *argv[]) {
	//LogCompenentEnable("out1",LOG_LEVEL_ALL);
	
	//NODE 
	//NodeContainer nodes;
	nodes.Create(1 + peer_cnt);
	
	// CSMA
	CsmaHelper csma;
	csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
	csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(6560)));
	NetDeviceContainer devices = csma.Install(nodes);
	
	// IP
	InternetStackHelper internet;
	internet.Install(nodes);
	Ipv4AddressHelper address;
	address.SetBase("10.1.1.0", "255.255.255.0");
	Ipv4InterfaceContainer interfaces = address.Assign(devices); //important
	
	setting(interfaces); // we will modify this function
	
	// let's go
	Simulator::Run();
	Simulator::Destroy();
}

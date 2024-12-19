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
#include <iostream>
#include <cassert>
#include <bitset>

const int peer_cnt = 10; // # of peer
const double t_begin = 1000; // simulation begin time
const double t_end = 2000; // simulation end time
const double time_per_chunk = 0.1; // time s.t. one chunk cover
const int len_of_chunk = 1024;
const int num_of_chunk = 1024; // number of chunk = total simulation time
const double acceptable_delay = 0.5;

using namespace ns3;
typedef std::string bytes;
typedef uint64_t ull;
using namespace std;
NS_LOG_COMPONENT_DEFINE("out1");
NodeContainer nodes;

string hexform(string a){
	string res;
	char x[]="0123456789ABCDEF";
	for(unsigned char c:a){
		res.push_back(x[c/16]);
		res.push_back(x[c%16]);
		res.push_back(' ');
	}
	return res.substr(0,71);
}
/*
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
*/

void tcp_fail(Ptr<Socket> socket){
	cout<<"FAIL\n";
	exit(99); // what can i do?
}
struct socketFunctor{
	int id;
	string payload;
	socketFunctor(int i,string p)
		:id(i),payload(p){}
	socketFunctor(const socketFunctor& y){
		id = y.id;
		payload = y.payload;
	}
	void operator()(Ptr<Socket> socket)const{
		Ptr<Packet> packet = Create<Packet>
			((uint8_t*)&payload[0],payload.size());
		socket->Send(packet);
		socket->Close();
		delete this;// um.. you will not use again I think
	}
};
void NewTcpSocket(Ptr<Node> node, Ipv4Address sip, uint16_t port,
	socketFunctor ff){
	//cout<<"NewTcpSocket "<<port<<endl;
	Ptr<Socket> socket = Socket::CreateSocket
		(node,TcpSocketFactory::GetTypeId());
	InetSocketAddress tcpAddr = InetSocketAddress(sip,port);
	socket->SetConnectCallback(
		MakeCallback(&socketFunctor::operator(),
			new socketFunctor(ff)
		),
		MakeCallback(&tcp_fail)
	);
	socket->Connect(tcpAddr);
}
void SendTcpPacket(int i, Ipv4Address sip, uint16_t port, string payload){
	//cout<<"SendTcpPacket from "<<i<<endl;
	NS_LOG_INFO(hexform(payload));
	NewTcpSocket(nodes.Get(i),sip,port,socketFunctor(i,payload));
}
void NewUdpSocket(Ptr<Node> node, Ipv4Address sip, uint16_t port,
	socketFunctor ff){
	Ptr<Socket> socket = Socket::CreateSocket
		(node,UdpSocketFactory::GetTypeId());
	InetSocketAddress udpAddr = InetSocketAddress(sip,port);
	socket->SetConnectCallback(
		MakeCallback(&socketFunctor::operator(),
			new socketFunctor(ff)
		),
		MakeCallback(&tcp_fail)
	);
	socket->Connect(udpAddr);
}
void SendUdpPacket(int i, Ipv4Address sip, uint16_t port, string payload){
	//NS_LOG_INFO(hexform(payload));
	NewUdpSocket(nodes.Get(i),sip,port,socketFunctor(i,payload));
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
	struct ClientMemory {
		enum{normal,errornomous,freerider,forger} my_type;
		Ipv4Address my_ip;
		uint16_t my_udp_port;
		uint16_t my_tcp_port;
		LinkProfile lp;
		vector<bytes> buffer;
		
		int integrity_failures = 0;
		int freerider_stack = 0;
		array<string,num_of_chunk> chunks;// Each client's chunk ownership
		array<string,num_of_chunk> tmp;
		vector<bool> chunkfaults;
	};
	ClientMemory arr[1+peer_cnt];
	// by stonejjun03
	void ClientSendChunk(int i,string chunk,ull child){
		auto[ip,port]=fromull(child);
		SendUdpPacket(i,ip,port,bytes("\x01")+chunk);
	}
	void ClientSendVal(int i,bytes payload){
		uint32_t x=*(uint32_t*)&payload[0];
		auto[ip,port]=fromull(*(ull*)&payload[4]);
		bytes code=payload.substr(12);
		int n=ssize(code);
		string res="\x01";
		if(n%5)
			res="\x00";
		else
			for(int j=0;j<n;j+=5)
				if(arr[i].chunks[x][*(uint32_t*)&code[j]]!=code[j+4])
					res="\x00";
		SendUdpPacket(i,ip,port,bytes("\x00")+payload.substr(0,4)+res);
	}
	void HandleReceivedUdpData(int i,bytes payload) {
		//cout<<'!'<<int(payload[0])<<endl;
		switch(payload[0]){
		case 0:
			if(payload[5]){
				int x=*(uint32_t*)&payload[1];
				arr[i].chunks[x]=arr[i].tmp[x];
				if(arr[i].lp[2])ClientSendChunk(i,
					arr[i].chunks[x],
					arr[i].lp[2]
				);
				if(arr[i].lp[3])ClientSendChunk(i,
					arr[i].chunks[x],
					arr[i].lp[3]
				);
			}
			else{
				auto[ip,port]=fromull(arr[i].lp[1]);
				SendUdpPacket(i,ip,port,
					bytes("\x03")
					+payload.substr(1,4)
				);
			}
			break;
		case 1:
			{
				uint32_t x=*(uint32_t*)&payload[1];
				arr[i].tmp[x]=payload.substr(1);
				if(arr[i].tmp[x].size()!=len_of_chunk+4){
					auto[ip,port]=fromull(arr[i].lp[1]);
					SendUdpPacket(i,ip,port,
						bytes("\x03")
						+payload.substr(1,4)
					);
				}
				else{
					
					bytes c="\x02____________";
					*(uint32_t*)&c[1]=x;
					*(ull*)&c[5]=toull(
						arr[i].my_ip,
						arr[i].my_udp_port
					);
					for(int t=0;t<3;t++){
						uint32_t y=rand()%len_of_chunk+4;
						bytes dc= "_____";
						*(uint32_t*)&dc[0]=y;
						dc[4]=arr[i].tmp[x][y];
						c+=dc;
					}
					auto[ip,port]=fromull(arr[i].lp[0]);
					SendUdpPacket(i,ip,port,
						c
					);
				}
			}
			break;
		case 2:
			ClientSendVal(i,payload.substr(1));
			break;
		case 3:
			uint32_t x=*(uint32_t*)&payload[1];
			if(!arr[i].chunks[x].empty())
				ClientSendChunk(i,
					arr[i].chunks[x],
					*(ull*)&payload[5]
				);
			break;
		}
	}
	void HandleReceivedTcpData(int i,bytes buffer) {
		arr[i].lp = LinkProfile(buffer);
	}
	void check_has_chunk(int i,int chunk_id){
		arr[i].chunkfaults.push_back
			(arr[i].chunks[chunk_id].empty());
	}
	void print_statistic(int i){
		
	}
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
		int tcp2idx(tcp_t x){
			return addr_idx[x];
		}
		PeerTree():arr(1){} // let [0] be data source ( central server )
		void init(tcp_t t,tcp_t u){
			cout<<"i\n";
			arr[0]={t,u}; //arr[0] should never changes..?
			addr_idx[t]=0;
		}
		addr_t one(){
			if(ssize(arr) > 1)
				return arr[1].second;
			return 0;
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
			if( i >= ssize(arr)) return {};
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
	map<ull,int> reputation;

	void addPeerQuery(const std::string payload){ // [ itself addr tcp|udp ]
		NS_LOG_INFO(hexform(payload));
		ull addr[2];
		memcpy(&addr,&payload[0],sizeof addr);
		// call addPeer
		auto res=server_address.addPeer(addr[0],addr[1]);
		
		for(auto[tcpa,profile]:res){
			auto[addr,port]=fromull(tcpa);
			SendTcpPacket(0, addr, port, profile.encode());
		}
	}
	void deletePeerQuery(const std::string payload){ // [ itself addr ]
		ull addrs[2];
		memcpy(&addrs,&payload[0],sizeof addrs);
		ull addr = addrs[0];
		ull pos = addrs[1];
		if(pos > 8)return;
		if(pos!=8){
			if(reputation[addr]<2)
				reputation[addr]++;
			else
				pos=8; // del itself
		}
		addr=server_address.tcp2idx(addr);
		if(pos==0) addr/=4;
		else if(pos==1) addr/=2;
		else if(pos==2) addr*=2;
		else if(pos==3) addr=addr*2+1;
		else if(pos==4) addr*=4;
		else if(pos==5) addr=addr*4+1;
		else if(pos==6) addr=addr*4+2;
		else if(pos==7) addr=addr*4+3;
		auto res=server_address.deletePeer(addr);
		for(auto[tcpa,profile]:res){
			auto[addr,port]=fromull(tcpa);
			SendTcpPacket(0, addr, port, profile.encode());
		}
	}
}

struct client_tcp_recv_functor{
	int id;
	client_tcp_recv_functor(){}
	client_tcp_recv_functor(const client_tcp_recv_functor& y){
		id = y.id;
	}
	void f(Ptr<const Packet> packet, const Address & address)const{
		string payload(packet->GetSize(),char(0));
		packet->CopyData((uint8_t*)&payload[0],packet->GetSize());
		//cout<<id<<':'<<hexform(payload)<<endl;
		Client::HandleReceivedTcpData(id,payload);
	}
	void fudp(Ptr<Socket> socket)const{
		Ptr<Packet> packet;
		Address address;
		while((packet=socket->RecvFrom(address))){
			string payload(packet->GetSize(),char(0));
			packet->CopyData((uint8_t*)&payload[0],packet->GetSize());
			//cout<<'u'<<id<<':'<<hexform(payload)<<endl;
			Client::HandleReceivedUdpData(id,payload);
		}
	}
} tcpff[1+peer_cnt];

void server_tcp_recv( Ptr<const Packet> packet, const Address & address){
	string payload(packet->GetSize(),char(0));
	packet->CopyData((uint8_t*)&payload[0],packet->GetSize());
	NS_LOG_INFO(hexform(payload));
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
void server_send_chunk(bytes chunk){ // chunk includes chunk id
	ull u = Server::server_address.one();
	if( u==0 ) return; // there is no peer to send
	auto[ip,port]=fromull(u);
	SendUdpPacket( 0 // server is node 0
		, ip
		, port
		, bytes("\x01")+chunk // 1 means data
	);
}
bytes chunks[num_of_chunk];
void server_validation(bytes payload){
	uint32_t x=*(uint32_t*)&payload[0];
	auto[ip,port]=fromull(*(ull*)&payload[4]);
	bytes code=payload.substr(12);
	int n=ssize(code);
	string res="\x01";
	if(n%5)
		res="\x00";
	else
		for(int j=0;j<n;j+=5)
			if(chunks[x][*(uint32_t*)&code[j]]!=code[j+4])
				res="\x00";
	SendUdpPacket(0,ip,port,bytes("\x00")+payload.substr(0,4)+res);
}
void server_udp_recv( Ptr<Socket> socket){
	Ptr<Packet> packet;
	Address address;
	while((packet=socket->RecvFrom(address))){
		string payload(packet->GetSize(),char(0));
		packet->CopyData((uint8_t*)&payload[0],packet->GetSize());
		switch(payload[0]){
		case 2:
			server_validation(payload.substr(1));
			break;
		case 3:
			server_send_chunk(chunks[*(uint32_t*)&payload[1]]);
			break;
		default:
			; // work similer with client
		}
	}
}

void did_you_recived_next_chunk(int i,int chunk_id){
	if(chunk_id==num_of_chunk)
		return;
	Simulator::Schedule(
		Seconds(Simulator::Now().GetSeconds()
		+time_per_chunk),
		&did_you_recived_next_chunk,
		i,chunk_id+1
	);
	Client::check_has_chunk(i,chunk_id);
}
void start_play_media(int i,int chunk_id_now){
	Simulator::Schedule(
		Seconds(Simulator::Now().GetSeconds()
		+acceptable_delay),
		&did_you_recived_next_chunk,
		i,chunk_id_now
	);
}
void client_init(int i, Ipv4Address sip, uint16_t port){
	ull t=toull(Client::arr[i].my_ip,Client::arr[i].my_tcp_port);
	ull v=toull(Client::arr[i].my_ip,Client::arr[i].my_udp_port);
	string payload(17,char(0));
	payload[0] = 0;
	*(ull*)&payload[1] = t;
	*(ull*)&payload[9] = v;
	SendTcpPacket(i,sip,port,payload);
}

void chunk_init(){
	for(int i=0;i<num_of_chunk;i++){
		chunks[i] = bytes(1028,'.');
		chunks[i][0]=i%256;
		chunks[i][1]=i/256%256;
		chunks[i][2]=i/256/256%256;
		chunks[i][3]=i/256/256/256%256;
		for(int j=4;j<1028;j++)
			chunks[i][j]=rand()%256;
	}
}
void setting(Ipv4InterfaceContainer ipif){
	uint16_t udpPort=8080, tcpPort = 8081; // tcp port of server ....and also of client now
	
	ApplicationContainer tcpServerApp[peer_cnt+1];
	for(int i=0;i<=peer_cnt;i++){
		Client::arr[i].my_ip = ipif.GetAddress(i);
		Client::arr[i].my_tcp_port = tcpPort;
		Client::arr[i].my_udp_port = udpPort;
		Address tcpLocalAddress(InetSocketAddress(Ipv4Address::GetAny(), tcpPort));
		PacketSinkHelper tcpServer("ns3::TcpSocketFactory", tcpLocalAddress);
		tcpServerApp[i] = tcpServer.Install(nodes.Get(i));
		tcpServerApp[i].Start(Seconds(t_begin - 0.1));
		tcpServerApp[i].Stop(Seconds(t_end));
		Ptr<PacketSink> sink =tcpServerApp[i].Get(0)->GetObject<PacketSink>();
		
		if(i){
			tcpff[i].id=i;
			sink->TraceConnectWithoutContext("Rx",
				MakeCallback(
					&client_tcp_recv_functor::f,
					tcpff+i
				)
			);
		}
		else
			sink->TraceConnectWithoutContext("Rx",
				MakeCallback(&server_tcp_recv)
			);
		
		Ptr<Socket> udp=Socket::CreateSocket(nodes.Get(i),
			UdpSocketFactory::GetTypeId());
		udp->Bind(InetSocketAddress(Ipv4Address::GetAny(), udpPort));
		if(i){
			udp->SetRecvCallback(MakeCallback(
				&client_tcp_recv_functor::fudp,
				tcpff+i
			));
		}
		else
			udp->SetRecvCallback(MakeCallback(
				&server_udp_recv
			));
		if(i){
			Simulator::Schedule(Seconds(t_begin + i),&client_init,
				i,ipif.GetAddress(0),tcpPort);
		}
		else{
			for(int i=0;i<num_of_chunk;i++){
				Simulator::Schedule(Seconds(t_begin+i*time_per_chunk),server_send_chunk,chunks[i]);
			}
			Server::server_address.init(
				toull(ipif.GetAddress(0),tcpPort),
				toull(ipif.GetAddress(0),udpPort)
			);
		}
	}
}

int main(int argc, char *argv[]) {
	//LogCompenentEnable("out1",LOG_LEVEL_ALL);
	
	Time::SetResolution(Time::NS);
	
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
	/*
	Ptr<Ipv4> ipv4_0 = nodes.Get(0)->GetObject<Ipv4>();
	Ptr<Ipv4> ipv4_1 = nodes.Get(1)->GetObject<Ipv4>();
	//ipv4_0->TraceConnectWithoutContext("PacketSend", MakeCallback(&PacketSent));
	//ipv4_0->TraceConnectWithoutContext("PacketReceive", MakeCallback(&PacketReceived));
	ipv4_1->TraceConnectWithoutContext("PacketSend", MakeCallback(&PacketSent));
	ipv4_1->TraceConnectWithoutContext("PacketReceive", MakeCallback(&PacketReceived));
	*/
	chunk_init();
	setting(interfaces); // we will modify this function
	
	// let's go
	Simulator::Run();
	Simulator::Destroy();
	
	for(int i=1; i<=peer_cnt; i++)
		Client::print_statistic(i);
}

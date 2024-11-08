#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"  // NetAnim

using namespace ns3;

#include <bits/stdc++.h>

void SendAddress(Ptr<Socket> socket, Ipv4Address address, uint16_t port) { // chatGPT generated
    std::ostringstream msg;
    msg << address << ":" << port;
    Ptr<Packet> packet = Create<Packet>((uint8_t *) msg.str().c_str(), msg.str().length());
    socket->Send(packet);
    std::cerr<<"sendaddress called"<<std::endl;
}

void ReceiveAddress(Ptr<Socket> socket) { // chatGPT generated
    Ptr<Packet> packet;
    Address from;
    while ((packet = socket->RecvFrom(from))) {
        uint8_t *buffer = new uint8_t[packet->GetSize() + 1];
        packet->CopyData(buffer, packet->GetSize());
        buffer[packet->GetSize()] = '\0';
        std::string addressStr = std::string((char*)buffer);
        //NS_LOG_INFO("Received address: " << addressStr);
        
        
        delete[] buffer;
    }
    std::cerr<<"recvaddress called"<<std::endl;
}

int main (int argc, char *argv[])
{
  //CommandLine cmd;
  //cmd.Parse (argc, argv);

  NodeContainer nodes;
  nodes.Create (2);

  PointToPointHelper pointToPoint;
  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
  pointToPoint.SetChannelAttribute ("Delay", StringValue ("2ms"));

  NetDeviceContainer devices;
  devices = pointToPoint.Install (nodes);

  InternetStackHelper stack;
  stack.Install (nodes);

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = address.Assign (devices);
  
  Ptr<Socket> serverSocket = Socket::CreateSocket(nodes.Get(0), TypeId::LookupByName("ns3::UdpSocketFactory"));
  InetSocketAddress serverAddr(interfaces.GetAddress(0), 8080);
  serverSocket->Bind(serverAddr);
  serverSocket->Listen();
  
  Ptr<Socket> clientSocket1 = Socket::CreateSocket(nodes.Get(1), TypeId::LookupByName("ns3::UdpSocketFactory"));
  clientSocket1->Connect(serverAddr);
  clientSocket1->SetRecvCallback(MakeCallback(&ReceiveAddress));
  
  //Ptr<Socket> clientSocket2 = Socket::CreateSocket(nodes.Get(2), TypeId::LookupByName("ns3::UdpSocketFactory"));
  //clientSocket2->Connect(serverAddr);
  //clientSocket2->SetRecvCallback(MakeCallback(&ReceiveAddress));
  
  Simulator::Schedule(Seconds(1.0), &SendAddress, clientSocket1, interfaces.GetAddress(1), 8080);
  //Simulator::Schedule(Seconds(1.5), &SendAddress, clientSocket2, interfaces.GetAddress(2), 8080);
  
  
  // NetAnim
  AnimationInterface anim ("result_yijw0930.xml");
  
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}
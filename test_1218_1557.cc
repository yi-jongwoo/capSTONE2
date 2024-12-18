#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

void RxCallback (Ptr<const Packet> packet, const Address &address) {
  std::cout << "Received packet from " << InetSocketAddress::ConvertFrom(address).GetIpv4() << std::endl;
}

int main (int argc, char *argv[]) {
  CommandLine cmd;
  cmd.Parse (argc, argv);

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

  uint16_t port = 9;
  Address serverAddress (InetSocketAddress (interfaces.GetAddress (1), port));
  PacketSinkHelper packetSinkHelper ("ns3::TcpSocketFactory", serverAddress);
  ApplicationContainer serverApps = packetSinkHelper.Install (nodes.Get (1));
  serverApps.Start (Seconds (1.0));
  serverApps.Stop (Seconds (10.0));

  OnOffHelper onOffHelper ("ns3::TcpSocketFactory", serverAddress);
  onOffHelper.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
  onOffHelper.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
  onOffHelper.SetAttribute ("DataRate", DataRateValue (DataRate ("1Mbps")));
  onOffHelper.SetAttribute ("PacketSize", UintegerValue (1024));
  ApplicationContainer clientApps = onOffHelper.Install (nodes.Get (0));
  clientApps.Start (Seconds (2.0));
  clientApps.Stop (Seconds (10.0));

  // MakeCallback 함수 사용 예제
  Ptr<Socket> recvSink = Socket::CreateSocket (nodes.Get (1), TcpSocketFactory::GetTypeId ());
  recvSink->Bind (InetSocketAddress (Ipv4Address::GetAny (), port));
  recvSink->SetRecvCallback (MakeCallback (&RxCallback));

  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}

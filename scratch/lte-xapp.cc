#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/lte-module.h"
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"

using namespace ns3;

int
main(int argc, char* argv[])
{
    Time simTime = Seconds(5);
    std::string xappAddress = "127.0.0.1";
    uint16_t xappPort = 9999;
    CommandLine commandLine(__FILE__);
    commandLine.AddValue("simTime", "Simulation duration", simTime);
    commandLine.AddValue("xappAddress", "External xApp IPv4 address", xappAddress);
    commandLine.AddValue("xappPort", "External xApp TCP port", xappPort);
    commandLine.Parse(argc, argv);

    LtePdcp::SetXAppSocket(xappAddress, xappPort);

    Ptr<LteHelper> lteHelper = CreateObject<LteHelper>();
    Ptr<PointToPointEpcHelper> epcHelper = CreateObject<PointToPointEpcHelper>();
    lteHelper->SetEpcHelper(epcHelper);

    NodeContainer enbNodes;
    enbNodes.Create(2);
    NodeContainer ueNodes;
    ueNodes.Create(1);
    NodeContainer remoteHostContainer;
    remoteHostContainer.Create(1);

    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(enbNodes);
    mobility.Install(ueNodes);
    mobility.Install(remoteHostContainer);
    enbNodes.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(0, 0, 0));
    enbNodes.Get(1)->GetObject<MobilityModel>()->SetPosition(Vector(500, 0, 0));
    ueNodes.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(20, 0, 0));

    InternetStackHelper internet;
    internet.Install(ueNodes);
    internet.Install(remoteHostContainer);
    NetDeviceContainer enbDevices = lteHelper->InstallEnbDevice(enbNodes);
    NetDeviceContainer ueDevices = lteHelper->InstallUeDevice(ueNodes);
    Ipv4InterfaceContainer ueInterfaces =
        epcHelper->AssignUeIpv4Address(NetDeviceContainer(ueDevices));
    Ipv4StaticRoutingHelper routing;
    routing.GetStaticRouting(ueNodes.Get(0)->GetObject<Ipv4>())
        ->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    lteHelper->Attach(ueDevices.Get(0), enbDevices.Get(0));

    Ptr<Node> pgw = epcHelper->GetPgwNode();
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", DataRateValue(DataRate("1Gb/s")));
    p2p.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
    NetDeviceContainer internetDevices = p2p.Install(pgw, remoteHostContainer.Get(0));
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("1.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer internetInterfaces = ipv4.Assign(internetDevices);
    routing.GetStaticRouting(remoteHostContainer.Get(0)->GetObject<Ipv4>())
        ->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);

    constexpr uint16_t port = 4000;
    PacketSinkHelper sink("ns3::UdpSocketFactory",
                          InetSocketAddress(Ipv4Address::GetAny(), port));
    ApplicationContainer server = sink.Install(remoteHostContainer.Get(0));
    UdpClientHelper client(internetInterfaces.GetAddress(1), port);
    client.SetAttribute("Interval", TimeValue(MilliSeconds(100)));
    client.SetAttribute("PacketSize", UintegerValue(256));
    client.SetAttribute("MaxPackets", UintegerValue(100000));
    ApplicationContainer traffic = client.Install(ueNodes.Get(0));

    server.Start(Seconds(0.5));
    traffic.Start(Seconds(0.8));
    traffic.Stop(simTime - MilliSeconds(100));
    Simulator::Stop(simTime);
    Simulator::Run();
    Simulator::Destroy();
    LtePdcp::DisableXAppSocket();
    return 0;
}

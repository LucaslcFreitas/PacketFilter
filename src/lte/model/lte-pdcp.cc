/*
 * Copyright (c) 2011-2012 Centre Tecnologic de Telecomunicacions de Catalunya (CTTC)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Manuel Requena <manuel.requena@cttc.es>
 */

#include "lte-pdcp.h"

#include "lte-pdcp-header.h"
#include "lte-pdcp-sap.h"
#include "lte-pdcp-tag.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <sstream>
#include <vector>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("LtePdcp");

/// LtePdcpSpecificLteRlcSapUser class
class LtePdcpSpecificLteRlcSapUser : public LteRlcSapUser
{
  public:
    /**
     * Constructor
     *
     * @param pdcp PDCP
     */
    LtePdcpSpecificLteRlcSapUser(LtePdcp* pdcp);

    // Interface provided to lower RLC entity (implemented from LteRlcSapUser)
    void ReceivePdcpPdu(Ptr<Packet> p) override;

  private:
    LtePdcpSpecificLteRlcSapUser();
    LtePdcp* m_pdcp; ///< the PDCP
};

LtePdcpSpecificLteRlcSapUser::LtePdcpSpecificLteRlcSapUser(LtePdcp* pdcp)
    : m_pdcp(pdcp)
{
}

LtePdcpSpecificLteRlcSapUser::LtePdcpSpecificLteRlcSapUser()
{
}

void
LtePdcpSpecificLteRlcSapUser::ReceivePdcpPdu(Ptr<Packet> p)
{
    m_pdcp->DoReceivePdu(p);
}

///////////////////////////////////////

NS_OBJECT_ENSURE_REGISTERED(LtePdcp);

namespace
{
bool g_xappEnabled = false;
std::string g_xappAddress;
uint16_t g_xappPort = 0;
int g_xappSocket = -1;

void
CloseXAppSocket()
{
    if (g_xappSocket >= 0)
    {
        close(g_xappSocket);
        g_xappSocket = -1;
    }
}

bool
ConnectXAppSocket()
{
    if (g_xappSocket >= 0)
    {
        return true;
    }

    g_xappSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (g_xappSocket < 0)
    {
        return false;
    }

    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    setsockopt(g_xappSocket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(g_xappSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(g_xappPort);
    if (inet_pton(AF_INET, g_xappAddress.c_str(), &server.sin_addr) != 1 ||
        connect(g_xappSocket, reinterpret_cast<sockaddr*>(&server), sizeof(server)) < 0)
    {
        CloseXAppSocket();
        return false;
    }
    return true;
}

std::string
PacketToHex(Ptr<Packet> packet)
{
    std::vector<uint8_t> bytes(packet->GetSize());
    if (!bytes.empty())
    {
        packet->CopyData(bytes.data(), bytes.size());
    }

    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes)
    {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 0x0f]);
    }
    return result;
}
} // namespace

LtePdcp::LtePdcp()
    : m_pdcpSapUser(nullptr),
      m_rlcSapProvider(nullptr),
      m_rnti(0),
      m_lcid(0),
      m_txSequenceNumber(0),
      m_rxSequenceNumber(0)
{
    NS_LOG_FUNCTION(this);
    m_pdcpSapProvider = new LtePdcpSpecificLtePdcpSapProvider<LtePdcp>(this);
    m_rlcSapUser = new LtePdcpSpecificLteRlcSapUser(this);
}

LtePdcp::~LtePdcp()
{
    NS_LOG_FUNCTION(this);
}

TypeId
LtePdcp::GetTypeId()
{
    static TypeId tid = TypeId("ns3::LtePdcp")
                            .SetParent<Object>()
                            .SetGroupName("Lte")
                            .AddTraceSource("TxPDU",
                                            "PDU transmission notified to the RLC.",
                                            MakeTraceSourceAccessor(&LtePdcp::m_txPdu),
                                            "ns3::LtePdcp::PduTxTracedCallback")
                            .AddTraceSource("RxPDU",
                                            "PDU received.",
                                            MakeTraceSourceAccessor(&LtePdcp::m_rxPdu),
                                            "ns3::LtePdcp::PduRxTracedCallback");
    return tid;
}

void
LtePdcp::DoDispose()
{
    NS_LOG_FUNCTION(this);
    delete (m_pdcpSapProvider);
    delete (m_rlcSapUser);
}

void
LtePdcp::SetXAppSocket(const std::string& address, uint16_t port)
{
    CloseXAppSocket();
    g_xappAddress = address;
    g_xappPort = port;
    g_xappEnabled = true;
}

void
LtePdcp::DisableXAppSocket()
{
    g_xappEnabled = false;
    CloseXAppSocket();
}

bool
LtePdcp::QueryXApp(Ptr<Packet> packet,
                   const std::string& direction,
                   uint16_t rnti,
                   uint8_t lcid)
{
    if (!g_xappEnabled || !ConnectXAppSocket())
    {
        return true;
    }

    std::ostringstream message;
    message << "{\"time_ns\":" << Simulator::Now().GetNanoSeconds()
            << ",\"direction\":\"" << direction << "\",\"rnti\":" << rnti
            << ",\"lcid\":" << static_cast<uint32_t>(lcid)
            << ",\"size\":" << packet->GetSize() << ",\"payload_hex\":\""
            << PacketToHex(packet) << "\"}\n";
    const std::string serialized = message.str();

    if (send(g_xappSocket, serialized.data(), serialized.size(), 0) < 0)
    {
        CloseXAppSocket();
        return true;
    }

    char response[256]{};
    const ssize_t received = recv(g_xappSocket, response, sizeof(response) - 1, 0);
    if (received <= 0)
    {
        CloseXAppSocket();
        return true;
    }

    response[received] = '\0';
    return std::string(response).find("\"action\":\"drop\"") == std::string::npos;
}

void
LtePdcp::SetRnti(uint16_t rnti)
{
    NS_LOG_FUNCTION(this << (uint32_t)rnti);
    m_rnti = rnti;
}

void
LtePdcp::SetLcId(uint8_t lcId)
{
    NS_LOG_FUNCTION(this << (uint32_t)lcId);
    m_lcid = lcId;
}

void
LtePdcp::SetLtePdcpSapUser(LtePdcpSapUser* s)
{
    NS_LOG_FUNCTION(this << s);
    m_pdcpSapUser = s;
}

LtePdcpSapProvider*
LtePdcp::GetLtePdcpSapProvider()
{
    NS_LOG_FUNCTION(this);
    return m_pdcpSapProvider;
}

void
LtePdcp::SetLteRlcSapProvider(LteRlcSapProvider* s)
{
    NS_LOG_FUNCTION(this << s);
    m_rlcSapProvider = s;
}

LteRlcSapUser*
LtePdcp::GetLteRlcSapUser()
{
    NS_LOG_FUNCTION(this);
    return m_rlcSapUser;
}

LtePdcp::Status
LtePdcp::GetStatus() const
{
    Status s;
    s.txSn = m_txSequenceNumber;
    s.rxSn = m_rxSequenceNumber;
    return s;
}

void
LtePdcp::SetStatus(Status s)
{
    m_txSequenceNumber = s.txSn;
    m_rxSequenceNumber = s.rxSn;
}

////////////////////////////////////////

void
LtePdcp::DoTransmitPdcpSdu(LtePdcpSapProvider::TransmitPdcpSduParameters params)
{
    NS_LOG_FUNCTION(this << m_rnti << static_cast<uint16_t>(m_lcid) << params.pdcpSdu->GetSize());
    Ptr<Packet> p = params.pdcpSdu;

    if (!QueryXApp(p, "uplink", m_rnti, m_lcid))
    {
        NS_LOG_INFO("External xApp dropped PDCP SDU");
        return;
    }

    // Sender timestamp
    PdcpTag pdcpTag(Simulator::Now());

    LtePdcpHeader pdcpHeader;
    pdcpHeader.SetSequenceNumber(m_txSequenceNumber);

    m_txSequenceNumber++;
    if (m_txSequenceNumber > m_maxPdcpSn)
    {
        m_txSequenceNumber = 0;
    }

    pdcpHeader.SetDcBit(LtePdcpHeader::DATA_PDU);
    p->AddHeader(pdcpHeader);
    p->AddByteTag(pdcpTag, 1, pdcpHeader.GetSerializedSize());

    m_txPdu(m_rnti, m_lcid, p->GetSize());

    LteRlcSapProvider::TransmitPdcpPduParameters txParams;
    txParams.rnti = m_rnti;
    txParams.lcid = m_lcid;
    txParams.pdcpPdu = p;

    NS_LOG_INFO("Transmitting PDCP PDU with header: " << pdcpHeader);
    m_rlcSapProvider->TransmitPdcpPdu(txParams);
}

void
LtePdcp::DoReceivePdu(Ptr<Packet> p)
{
    NS_LOG_FUNCTION(this << m_rnti << (uint32_t)m_lcid << p->GetSize());

    Ptr<Packet> inspected = p->Copy();
    LtePdcpHeader inspectedHeader;
    inspected->RemoveHeader(inspectedHeader);
    if (!QueryXApp(inspected, "downlink", m_rnti, m_lcid))
    {
        NS_LOG_INFO("External xApp dropped PDCP SDU");
        return;
    }

    // Receiver timestamp
    PdcpTag pdcpTag;
    Time delay;
    p->FindFirstMatchingByteTag(pdcpTag);
    delay = Simulator::Now() - pdcpTag.GetSenderTimestamp();
    m_rxPdu(m_rnti, m_lcid, p->GetSize(), delay.GetNanoSeconds());

    LtePdcpHeader pdcpHeader;
    p->RemoveHeader(pdcpHeader);
    NS_LOG_LOGIC("PDCP header: " << pdcpHeader);

    m_rxSequenceNumber = pdcpHeader.GetSequenceNumber() + 1;
    if (m_rxSequenceNumber > m_maxPdcpSn)
    {
        m_rxSequenceNumber = 0;
    }

    LtePdcpSapUser::ReceivePdcpSduParameters params;
    params.pdcpSdu = p;
    params.rnti = m_rnti;
    params.lcid = m_lcid;
    m_pdcpSapUser->ReceivePdcpSdu(params);
}

} // namespace ns3

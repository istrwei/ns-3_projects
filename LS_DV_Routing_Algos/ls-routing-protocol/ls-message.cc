/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "ns3/ls-message.h"
#include "ns3/log.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("LSMessage");
NS_OBJECT_ENSURE_REGISTERED (LSMessage);

LSMessage::LSMessage ()
{
}

LSMessage::~LSMessage ()
{
}

LSMessage::LSMessage (LSMessage::MessageType messageType, uint32_t sequenceNumber, uint8_t ttl, Ipv4Address originatorAddress)
{
  m_messageType = messageType;
  m_sequenceNumber = sequenceNumber;
  m_ttl = ttl;
  m_originatorAddress = originatorAddress;
}

TypeId
LSMessage::GetTypeId (void)
{
  static TypeId tid = TypeId ("LSMessage")
    .SetParent<Header> ()
    .AddConstructor<LSMessage> ()
  ;
  return tid;
}

TypeId
LSMessage::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}


uint32_t
LSMessage::GetSerializedSize (void) const
{
  // size of messageType, sequence number, originator address, ttl
  uint32_t size = sizeof (uint8_t) + sizeof (uint32_t) + IPV4_ADDRESS_SIZE + sizeof (uint8_t);
  switch (m_messageType)
    {
      case PING_REQ:
        size += m_message.pingReq.GetSerializedSize ();
        break;
      case PING_RSP:
        size += m_message.pingRsp.GetSerializedSize ();
        break;


       // NEW method type
      case NDISC_RSP:
        size += m_message.ndiscRsp.GetSerializedSize ();
        break;

      case NDISC_REQ:
        size += m_message.ndiscReq.GetSerializedSize ();
        break;

      case LSP:
        size += m_message.lsp.GetSerializedSize ();
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

void
LSMessage::Print (std::ostream &os) const
{
  os << "\n****LSMessage Dump****\n" ;
  os << "messageType: " << m_messageType << "\n";
  os << "sequenceNumber: " << m_sequenceNumber << "\n";
  os << "ttl: " << m_ttl << "\n";
  os << "originatorAddress: " << m_originatorAddress << "\n";
  os << "PAYLOAD:: \n";

  switch (m_messageType)
    {
      case PING_REQ:
        m_message.pingReq.Print (os);
        break;
      case PING_RSP:
        m_message.pingRsp.Print (os);
        break;

     case NDISC_REQ:
       m_message.ndiscReq.Print (os);
       break;
     case NDISC_RSP:
       m_message.ndiscRsp.Print (os);
       break;
     case LSP:
    	 m_message.lsp.Print(os);
    	 break;
      default:
        break;
    }
  os << "\n****END OF MESSAGE****\n";
}

void
LSMessage::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteU8 (m_messageType);
  i.WriteHtonU32 (m_sequenceNumber);
  i.WriteU8 (m_ttl);
  i.WriteHtonU32 (m_originatorAddress.Get ());

  switch (m_messageType)
    {
      case PING_REQ:
        m_message.pingReq.Serialize (i);
        break;
      case PING_RSP:
        m_message.pingRsp.Serialize (i);
        break;

      case NDISC_REQ:
        m_message.ndiscReq.Serialize (i);
        break;
      case NDISC_RSP:
        m_message.ndiscRsp.Serialize (i);
        break;

      case LSP:
         m_message.lsp.Serialize (i);
         break;
      default:
        NS_ASSERT (false);
    }
}

uint32_t
LSMessage::Deserialize (Buffer::Iterator start)
{
  uint32_t size;
  Buffer::Iterator i = start;
  m_messageType = (MessageType) i.ReadU8 ();
  m_sequenceNumber = i.ReadNtohU32 ();
  m_ttl = i.ReadU8 ();
  m_originatorAddress = Ipv4Address (i.ReadNtohU32 ());

  size = sizeof (uint8_t) + sizeof (uint32_t) + sizeof (uint8_t) + IPV4_ADDRESS_SIZE;

  switch (m_messageType)
    {
      case PING_REQ:
        size += m_message.pingReq.Deserialize (i);
        break;
      case PING_RSP:
        size += m_message.pingRsp.Deserialize (i);
        break;

      case NDISC_REQ:
        size += m_message.ndiscReq.Deserialize (i);
        break;
      case NDISC_RSP:
        size += m_message.ndiscRsp.Deserialize (i);
        break;

      case LSP:
        size += m_message.lsp.Deserialize (i);
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

/* PING_REQ */

uint32_t
LSMessage::PingReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
LSMessage::PingReq::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}


void
LSMessage::PingReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
LSMessage::PingReq::Deserialize (Buffer::Iterator &start)
{
  destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingReq::GetSerializedSize ();
}

void
LSMessage::SetPingReq (Ipv4Address destinationAddress, std::string pingMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = PING_REQ;
    }
  else
    {
      NS_ASSERT (m_messageType == PING_REQ);
    }
  m_message.pingReq.destinationAddress = destinationAddress;
  m_message.pingReq.pingMessage = pingMessage;
}

LSMessage::PingReq
LSMessage::GetPingReq ()
{
  return m_message.pingReq;
}

/* PING_RSP */

uint32_t
LSMessage::PingRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
LSMessage::PingRsp::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
LSMessage::PingRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
LSMessage::PingRsp::Deserialize (Buffer::Iterator &start)
{
  destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingRsp::GetSerializedSize ();
}

void
LSMessage::SetPingRsp (Ipv4Address destinationAddress, std::string pingMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = PING_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == PING_RSP);
    }
  m_message.pingRsp.destinationAddress = destinationAddress;
  m_message.pingRsp.pingMessage = pingMessage;
}

LSMessage::PingRsp
LSMessage::GetPingRsp ()
{
  return m_message.pingRsp;
}


//

/* neighbor discover request */
uint32_t
LSMessage::NDISC_Req::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + helloMessage.length();
  return size;
}

void
LSMessage::NDISC_Req::Print (std::ostream &os) const
{
  os << "Neighbor Discover Req:: Message: " << helloMessage << "\n";
}

void
LSMessage::NDISC_Req::Serialize (Buffer::Iterator &start) const
{
 // start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (helloMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (helloMessage.c_str())), helloMessage.length());
}

uint32_t
LSMessage::NDISC_Req::Deserialize (Buffer::Iterator &start)
{
 // destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  helloMessage = std::string (str, length);
  free (str);
  return NDISC_Req::GetSerializedSize ();
}

void
LSMessage::SetNdiscReq (std::string helloMessage)
{
  if (m_messageType == 3)
    {
      m_messageType = NDISC_REQ;
    }
  else
    {
      NS_ASSERT (m_messageType == NDISC_REQ);
    }
//  m_message.pingReq.destinationAddress = destinationAddress;
  m_message.ndiscReq.helloMessage = helloMessage;
}

LSMessage::NDISC_Req
LSMessage::GetNdiscReq ()
{
  return m_message.ndiscReq;
}



/* neighbor discover response*/

uint32_t
LSMessage::NDISC_Rsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof(uint16_t) + helloMessage.length();
  return size;
}

void
LSMessage::NDISC_Rsp::Print (std::ostream &os) const
{
  os << "neighbor discover response:: Message: " << helloMessage << "\n";
}

void
LSMessage::NDISC_Rsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (helloMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (helloMessage.c_str())), helloMessage.length());
}

uint32_t
LSMessage::NDISC_Rsp::Deserialize (Buffer::Iterator &start)
{
  destinationAddress = Ipv4Address (start.ReadNtohU32 ());
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  helloMessage = std::string (str, length);
  free (str);
  return NDISC_Rsp::GetSerializedSize ();
}

void
LSMessage::SetNdiscRsp (Ipv4Address destinationAddress, std::string helloMessage)
{
  if (m_messageType == 4)
    {
      m_messageType = NDISC_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == NDISC_RSP);
    }
  m_message.ndiscRsp.destinationAddress = destinationAddress;
  m_message.ndiscRsp.helloMessage = helloMessage;
}

LSMessage::NDISC_Rsp
LSMessage::GetNdiscRsp ()
{
  return m_message.ndiscRsp;
}



/**************************  LSP  ******************************/

uint32_t
LSMessage::LSP_msg::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof(uint16_t) + 4*sizeof(uint32_t)*neighborTable.size() + sizeof(uint32_t);

  return size;
}

void
LSMessage::LSP_msg::Print (std::ostream &os) const
{
  os << "LSP message from node " << nodeAddress ;
}


void
LSMessage::LSP_msg::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (nodeAddress.Get ());

  //write neighbor table
  start.WriteU16 (neighborTable.size());

  // only pass in the neighbor address and the cost,  can add them on if other variables of the table is needed
	 for(std::map<Ipv4Address, NeighborTableEntry>::const_iterator itera = neighborTable.begin ();
	             itera != neighborTable.end (); itera++)
	  {
		 start.WriteHtonU32 (itera->first.Get());
		 start.WriteHtonU32 (itera->second.neighborAddr.Get());
		 start.WriteHtonU32 (itera->second.interfaceAddr.Get());
		 start.WriteHtonU32 (itera->second.cost);

	  }

	 start.WriteHtonU32 (timeStamp);
}

uint32_t
LSMessage::LSP_msg::Deserialize (Buffer::Iterator &start)
{
  nodeAddress = Ipv4Address (start.ReadNtohU32 ());

  uint16_t mapSize = start.ReadU16 ();

  for (size_t i = 0; i < mapSize; ++i)
  {
	  NeighborTableEntry entry;
	  Ipv4Address key;

	  key = Ipv4Address (start.ReadNtohU32 ());
	  entry.neighborAddr = Ipv4Address (start.ReadNtohU32 ());
	  entry.interfaceAddr = Ipv4Address (start.ReadNtohU32 ());
	  entry.cost = start.ReadNtohU32 ();

	  neighborTable[key] = entry;
  }
  timeStamp = start.ReadNtohU32 ();
  return LSP_msg::GetSerializedSize ();
}

void
LSMessage::SetLSP (Ipv4Address nodeAddress , std::map<Ipv4Address, NeighborTableEntry> neighborTable)
{
  if (m_messageType == 5)
    {
      m_messageType = LSP;
    }
  else
    {

      NS_ASSERT (m_messageType == LSP);
    }
  m_message.lsp.nodeAddress = nodeAddress;
  m_message.lsp.neighborTable = neighborTable;
}

LSMessage::LSP_msg
LSMessage::GetLSP ()
{
  return m_message.lsp;
}

void
LSMessage::SetTimeStamp(uint32_t timeStamp)
{
	m_message.lsp.timeStamp = timeStamp;
}

uint32_t
LSMessage::GetTimeStamp()
{

	return m_message.lsp.timeStamp;
}


//////////////////////////////////////////////////////////////////////////////

void
LSMessage::SetMessageType (MessageType messageType)
{
  m_messageType = messageType;
}

LSMessage::MessageType
LSMessage::GetMessageType () const
{
  return m_messageType;
}

void
LSMessage::SetSequenceNumber (uint32_t sequenceNumber)
{
  m_sequenceNumber = sequenceNumber;
}

uint32_t
LSMessage::GetSequenceNumber (void) const
{
  return m_sequenceNumber;
}

void
LSMessage::SetTTL (uint8_t ttl)
{
  m_ttl = ttl;
}

uint8_t
LSMessage::GetTTL (void) const
{
  return m_ttl;
}

void
LSMessage::SetOriginatorAddress (Ipv4Address originatorAddress)
{
  m_originatorAddress = originatorAddress;
}

Ipv4Address
LSMessage::GetOriginatorAddress (void) const
{
  return m_originatorAddress;
}


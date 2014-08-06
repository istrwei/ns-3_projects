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

#include "ns3/dv-message.h"
#include "ns3/log.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("DVMessage");
NS_OBJECT_ENSURE_REGISTERED (DVMessage);

DVMessage::DVMessage ()
{
}

DVMessage::~DVMessage ()
{
}

DVMessage::DVMessage (DVMessage::MessageType messageType, uint32_t sequenceNumber, uint8_t ttl, Ipv4Address originatorAddress)
{
  m_messageType = messageType;
  m_sequenceNumber = sequenceNumber;
  m_ttl = ttl;
  m_originatorAddress = originatorAddress;
}

TypeId
DVMessage::GetTypeId (void)
{
  static TypeId tid = TypeId ("DVMessage")
    .SetParent<Header> ()
    .AddConstructor<DVMessage> ()
  ;
  return tid;
}

TypeId
DVMessage::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}


uint32_t
DVMessage::GetSerializedSize (void) const
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

      case DV:
        size += m_message.dvMsg.GetSerializedSize ();
        break;

      default:
        NS_ASSERT (false);
    }
  return size;
}

void
DVMessage::Print (std::ostream &os) const
{
  os << "\n****DVMessage Dump****\n" ;
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

      case DV:
        m_message.dvMsg.Print (os);
         break;
      default:
        break;
    }
  os << "\n****END OF MESSAGE****\n";
}

void
DVMessage::Serialize (Buffer::Iterator start) const
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
      case DV:
        m_message.dvMsg.Serialize (i);
        break;
      default:
        NS_ASSERT (false);
    }
}

uint32_t
DVMessage::Deserialize (Buffer::Iterator start)
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

      case DV:
        size += m_message.dvMsg.Deserialize (i);
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

/* PING_REQ */

uint32_t
DVMessage::PingReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
DVMessage::PingReq::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}


void
DVMessage::PingReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
DVMessage::PingReq::Deserialize (Buffer::Iterator &start)
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
DVMessage::SetPingReq (Ipv4Address destinationAddress, std::string pingMessage)
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

DVMessage::PingReq
DVMessage::GetPingReq ()
{
  return m_message.pingReq;
}

/* PING_RSP */

uint32_t
DVMessage::PingRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
DVMessage::PingRsp::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
DVMessage::PingRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
DVMessage::PingRsp::Deserialize (Buffer::Iterator &start)
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
DVMessage::SetPingRsp (Ipv4Address destinationAddress, std::string pingMessage)
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

DVMessage::PingRsp
DVMessage::GetPingRsp ()
{
  return m_message.pingRsp;
}


//

/* neighbor discover request */
uint32_t
DVMessage::NDISC_Req::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + helloMessage.length();
  return size;
}

void
DVMessage::NDISC_Req::Print (std::ostream &os) const
{
  os << "Neighbor Discover Req:: Message: " << helloMessage << "\n";
}

void
DVMessage::NDISC_Req::Serialize (Buffer::Iterator &start) const
{
 // start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (helloMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (helloMessage.c_str())), helloMessage.length());
}

uint32_t
DVMessage::NDISC_Req::Deserialize (Buffer::Iterator &start)
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
DVMessage::SetNdiscReq (std::string helloMessage)
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

DVMessage::NDISC_Req
DVMessage::GetNdiscReq ()
{
  return m_message.ndiscReq;
}



/* neighbor discover response*/

uint32_t
DVMessage::NDISC_Rsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof(uint16_t) + helloMessage.length();
  return size;
}

void
DVMessage::NDISC_Rsp::Print (std::ostream &os) const
{
  os << "neighbor discover response:: Message: " << helloMessage << "\n";
}

void
DVMessage::NDISC_Rsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (destinationAddress.Get ());
  start.WriteU16 (helloMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (helloMessage.c_str())), helloMessage.length());
}

uint32_t
DVMessage::NDISC_Rsp::Deserialize (Buffer::Iterator &start)
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
DVMessage::SetNdiscRsp (Ipv4Address destinationAddress, std::string helloMessage)
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

DVMessage::NDISC_Rsp
DVMessage::GetNdiscRsp ()
{
  return m_message.ndiscRsp;
}

/*-----------dv------------------*/

uint32_t
DVMessage::DV_msg::GetSerializedSize (void) const
{
  uint32_t size;
  size = IPV4_ADDRESS_SIZE + sizeof(uint16_t) + 4*sizeof(uint32_t)*DvTable.size();

  return size;
}

void
DVMessage::DV_msg::Print (std::ostream &os) const
{
  os << "DV message from node " << nodeAddress ;
}


void
DVMessage::DV_msg::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (nodeAddress.Get ());

  //write neighbor table
  start.WriteU16 (DvTable.size());

  // only pass in the neighbor address and the cost,  can add them on if other variables of the table is needed
	 for(std::map<Ipv4Address, DvEntry>::const_iterator itera = DvTable.begin ();
	             itera != DvTable.end (); itera++)
	  {
		 start.WriteHtonU32 (itera->first.Get());      // destination address
		 start.WriteHtonU32 (itera->second.next.Get());
		 start.WriteHtonU32 (itera->second.cost);
		 start.WriteHtonU32 (itera->second.count);

	  }
}

uint32_t
DVMessage::DV_msg::Deserialize (Buffer::Iterator &start)
{
  nodeAddress = Ipv4Address (start.ReadNtohU32 ());

  uint16_t mapSize = start.ReadU16 ();

  for (size_t i = 0; i < mapSize; ++i)
  {
	  DvEntry entry;
	  Ipv4Address key;

	  key = Ipv4Address (start.ReadNtohU32 ());
	  entry.next = Ipv4Address (start.ReadNtohU32 ());
	  entry.cost = start.ReadNtohU32 ();
	  entry.count = start.ReadNtohU32 ();

	  DvTable[key] = entry;
  }
  return DV_msg::GetSerializedSize ();
}

void
DVMessage::SetDV (Ipv4Address nodeAddress , std::map<Ipv4Address, DvEntry> DvTable)
{
  if (m_messageType == 5)
    {
      m_messageType = DV;
    }
  else
    {

      NS_ASSERT (m_messageType == DV);
    }
  m_message.dvMsg.nodeAddress = nodeAddress;
  m_message.dvMsg.DvTable = DvTable;
}

DVMessage::DV_msg
DVMessage::GetDV ()
{
  return m_message.dvMsg;
}

//////////////////////////////////////////////////////////////////////////////

void
DVMessage::SetMessageType (MessageType messageType)
{
  m_messageType = messageType;
}

DVMessage::MessageType
DVMessage::GetMessageType () const
{
  return m_messageType;
}

void
DVMessage::SetSequenceNumber (uint32_t sequenceNumber)
{
  m_sequenceNumber = sequenceNumber;
}

uint32_t
DVMessage::GetSequenceNumber (void) const
{
  return m_sequenceNumber;
}

void
DVMessage::SetTTL (uint8_t ttl)
{
  m_ttl = ttl;
}

uint8_t
DVMessage::GetTTL (void) const
{
  return m_ttl;
}

void
DVMessage::SetOriginatorAddress (Ipv4Address originatorAddress)
{
  m_originatorAddress = originatorAddress;
}

Ipv4Address
DVMessage::GetOriginatorAddress (void) const
{
  return m_originatorAddress;
}


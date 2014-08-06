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

#include "ns3/penn-chord-message.h"
#include "ns3/log.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("PennChordMessage");
NS_OBJECT_ENSURE_REGISTERED (PennChordMessage);

PennChordMessage::PennChordMessage ()
{
}

PennChordMessage::~PennChordMessage ()
{
}

PennChordMessage::PennChordMessage (PennChordMessage::MessageType messageType, uint32_t transactionId)
{
  m_messageType = messageType;
  m_transactionId = transactionId;
}

TypeId
PennChordMessage::GetTypeId (void)
{
  static TypeId tid = TypeId ("PennChordMessage")
    .SetParent<Header> ()
    .AddConstructor<PennChordMessage> ()
  ;
  return tid;
}

TypeId
PennChordMessage::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}


uint32_t
PennChordMessage::GetSerializedSize (void) const
{
  // size of messageType, transaction id
  uint32_t size = sizeof (uint8_t) + sizeof (uint32_t);
  switch (m_messageType)
    {
      case PING_REQ:
        size += m_message.pingReq.GetSerializedSize ();
        break;
      case PING_RSP:
        size += m_message.pingRsp.GetSerializedSize ();
        break;
      case LOOKUP_MSG:
        size += m_message.lookupMsg.GetSerializedSize ();
        break;
      case INVERTEDLIST_MSG:
        size += m_message.invertedListMsg.GetSerializedSize ();
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

void
PennChordMessage::Print (std::ostream &os) const
{
  os << "\n****PennChordMessage Dump****\n" ;
  os << "messageType: " << m_messageType << "\n";
  os << "transactionId: " << m_transactionId << "\n";
  os << "PAYLOAD:: \n";

  switch (m_messageType)
    {
      case PING_REQ:
        m_message.pingReq.Print (os);
        break;
      case PING_RSP:
        m_message.pingRsp.Print (os);
      case LOOKUP_MSG:
        m_message.lookupMsg.Print (os);
        break;
      case INVERTEDLIST_MSG:
        m_message.lookupMsg.Print (os);
        break;
      default:
        break;
    }
  os << "\n****END OF MESSAGE****\n";
}

void
PennChordMessage::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteU8 (m_messageType);
  i.WriteHtonU32 (m_transactionId);

  switch (m_messageType)
    {
      case PING_REQ:
        m_message.pingReq.Serialize (i);
        break;
      case PING_RSP:
        m_message.pingRsp.Serialize (i);
      case LOOKUP_MSG:
        m_message.lookupMsg.Serialize (i);
        break;
      case INVERTEDLIST_MSG:
        m_message.invertedListMsg.Serialize (i);
        break;
      default:
        NS_ASSERT (false);
    }
}

uint32_t
PennChordMessage::Deserialize (Buffer::Iterator start)
{
  uint32_t size;
  Buffer::Iterator i = start;
  m_messageType = (MessageType) i.ReadU8 ();
  m_transactionId = i.ReadNtohU32 ();

  size = sizeof (uint8_t) + sizeof (uint32_t);

  switch (m_messageType)
    {
      case PING_REQ:
        size += m_message.pingReq.Deserialize (i);
        break;
      case PING_RSP:
        size += m_message.pingRsp.Deserialize (i);
      case LOOKUP_MSG:
        m_message.lookupMsg.Deserialize (i);
        break;
      case INVERTEDLIST_MSG:
        m_message.invertedListMsg.Deserialize (i);
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

/* PING_REQ */

uint32_t
PennChordMessage::PingReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
PennChordMessage::PingReq::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
PennChordMessage::PingReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
PennChordMessage::PingReq::Deserialize (Buffer::Iterator &start)
{
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingReq::GetSerializedSize ();
}

void
PennChordMessage::SetPingReq (std::string pingMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = PING_REQ;
    }
  else
    {
      NS_ASSERT (m_messageType == PING_REQ);
    }
  m_message.pingReq.pingMessage = pingMessage;
}

PennChordMessage::PingReq
PennChordMessage::GetPingReq ()
{
  return m_message.pingReq;
}

/* PING_RSP */

uint32_t
PennChordMessage::PingRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
PennChordMessage::PingRsp::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
PennChordMessage::PingRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
PennChordMessage::PingRsp::Deserialize (Buffer::Iterator &start)
{
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingRsp::GetSerializedSize ();
}

void
PennChordMessage::SetPingRsp (std::string pingMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = PING_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == PING_RSP);
    }
  m_message.pingRsp.pingMessage = pingMessage;
}

PennChordMessage::PingRsp
PennChordMessage::GetPingRsp ()
{
  return m_message.pingRsp;
}

// LOOKUP_MSG

uint32_t
PennChordMessage::LookupMsg::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t) + key.length() + sizeof(uint16_t) + lookupMessage.length();
  return size;
}

void
PennChordMessage::LookupMsg::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << lookupMessage << "\n";
}

void
PennChordMessage::LookupMsg::Serialize (Buffer::Iterator &start) const
{
  start.WriteHtonU32 (orinNode.Get ());
  start.WriteHtonU32 (resultNode.Get ());
  start.WriteU16 (key.length ());
  start.Write ((uint8_t *) (const_cast<char*> (key.c_str())), key.length());
  start.WriteU16 (lookupMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (lookupMessage.c_str())), lookupMessage.length());
}

uint32_t
PennChordMessage::LookupMsg::Deserialize (Buffer::Iterator &start)
{

  orinNode = Ipv4Address (start.ReadNtohU32 ());
  resultNode = Ipv4Address (start.ReadNtohU32 ());

  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  key = std::string (str, length);
  free (str);

  length = start.ReadU16 ();
  str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  lookupMessage = std::string (str, length);
  free (str);
  return LookupMsg::GetSerializedSize ();
}

void
PennChordMessage::SetLookupMsg (Ipv4Address resultNode, std::string message)
{
  if (m_messageType == 0)
    {
      m_messageType = LOOKUP_MSG;
    }
  else
    {
      NS_ASSERT (m_messageType == LOOKUP_MSG);
    }
  m_message.lookupMsg.lookupMessage = message;
  m_message.lookupMsg.resultNode = resultNode;

}


void
PennChordMessage::SetLookupMsg (std::string message)
{
  if (m_messageType == 0)
    {
      m_messageType = LOOKUP_MSG;
    }
  else
    {
      NS_ASSERT (m_messageType == LOOKUP_MSG);
    }
  m_message.lookupMsg.lookupMessage = message;
}

void
PennChordMessage::SetLookupMsg (std::string key, Ipv4Address orinNode,std::string message)
{
  if (m_messageType == 0)
    {
      m_messageType = LOOKUP_MSG;
    }
  else
    {
      NS_ASSERT (m_messageType == LOOKUP_MSG);
    }
  m_message.lookupMsg.orinNode = orinNode;
  m_message.lookupMsg.key = key;
  m_message.lookupMsg.lookupMessage = message;

}

PennChordMessage::LookupMsg
PennChordMessage::GetLookupMsg ()
{
  return m_message.lookupMsg;
}

// InvertedList
uint32_t
PennChordMessage::InvertedListMsg::GetSerializedSize (void) const
{
  uint32_t size;
  uint32_t invertedListSizeTotal = 0;

  for(std::map<std::string, std::vector<std::string> >::const_iterator itera = invertedList.begin ();
	             itera != invertedList.end (); itera++)
  {
	  std::string tempKey = itera->first;
	  invertedListSizeTotal += sizeof(uint16_t) + tempKey.length() + sizeof(uint16_t);

	  for(uint16_t i=0;i<itera->second.size();i++)
	  {
		  std::string docIDTemp = itera->second[i];
		  invertedListSizeTotal += sizeof(uint16_t) + docIDTemp.length();
	  }

  }

  size = sizeof(uint16_t) + invertedListMsg.length() + sizeof(uint16_t)
	 + invertedListSizeTotal;
  return size;
}

void
PennChordMessage::InvertedListMsg::Print (std::ostream &os) const
{
  os << "InvertedListMsg:: Message: " << invertedListMsg << "\n";
}

void
PennChordMessage::InvertedListMsg::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (invertedListMsg.length ());
  start.Write ((uint8_t *) (const_cast<char*> (invertedListMsg.c_str())), invertedListMsg.length());

  start.WriteU16 (invertedList.size());

  for(std::map<std::string, std::vector<std::string> >::const_iterator itera = invertedList.begin ();
	             itera != invertedList.end (); itera++)
  {
	  std::string key = itera->first;
	  std::vector<std::string> docIDs = itera->second;

	  start.WriteU16 (key.length ());
	  start.Write ((uint8_t *) (const_cast<char*> (key.c_str())), key.length());
	  start.WriteU16 (docIDs.size());

	  for(uint16_t i=0;i<docIDs.size();i++)
	  {
		  std::string docIDTemp = docIDs[i];
		  start.WriteU16 (docIDTemp.length ());
		  start.Write ((uint8_t *) (const_cast<char*> (docIDTemp.c_str())), docIDTemp.length());
	  }
  }

}

uint32_t
PennChordMessage::InvertedListMsg::Deserialize (Buffer::Iterator &start)
{
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  invertedListMsg = std::string (str, length);
  free (str);

  uint16_t listSize = start.ReadU16 ();

  for(int i=0;i<listSize;i++)
  {
	  uint16_t lengthList = start.ReadU16 ();
	  char* strList = (char*) malloc (lengthList);
	  start.Read ((uint8_t*)strList, lengthList);
	  std::string key = std::string (strList, lengthList);
	  free (strList);

	  uint16_t vectorSize = start.ReadU16 ();
	  std::vector<std::string> docIDs;
  	  for(int j=0;j<vectorSize;j++)
	  {
		  uint16_t lengthVector = start.ReadU16 ();
		  char* strVector =  (char*) malloc (lengthVector);
		  start.Read ((uint8_t*)strVector, lengthVector);
		  std::string docIDTemp = std::string (strVector, lengthVector);
		  docIDs.push_back(docIDTemp);
		  free (strVector);
	  }
	  invertedList[key] = docIDs;
  }

  return InvertedListMsg::GetSerializedSize ();
}

void
PennChordMessage::SetInvertedListMsg (std::map<std::string, std::vector<std::string> > invertedList,
		std::string invertedListMsg)
{
  if (m_messageType == 0)
    {
      m_messageType = INVERTEDLIST_MSG;
    }
  else
    {
      NS_ASSERT (m_messageType == INVERTEDLIST_MSG);
    }
  m_message.invertedListMsg.invertedListMsg = invertedListMsg;
  m_message.invertedListMsg.invertedList = invertedList;
}

PennChordMessage::InvertedListMsg
PennChordMessage::GetInvertedListMsg ()
{
  return m_message.invertedListMsg;
}


//
//

void
PennChordMessage::SetMessageType (MessageType messageType)
{
  m_messageType = messageType;
}

PennChordMessage::MessageType
PennChordMessage::GetMessageType () const
{
  return m_messageType;
}

void
PennChordMessage::SetTransactionId (uint32_t transactionId)
{
  m_transactionId = transactionId;
}

uint32_t
PennChordMessage::GetTransactionId (void) const
{
  return m_transactionId;
}


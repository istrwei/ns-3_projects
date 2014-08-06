/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 University of Pennsylvania
 *
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


#include "penn-chord.h"

#include "ns3/random-variable.h"
#include "ns3/inet-socket-address.h"
#include "stdio.h"
#include "inttypes.h"
#include <ios>
#include <sstream>
#include <openssl/sha.h>

#include <fstream>
using namespace ns3;

TypeId
PennChord::GetTypeId ()
{
  static TypeId tid = TypeId ("PennChord")
    .SetParent<PennApplication> ()
    .AddConstructor<PennChord> ()
    .AddAttribute ("AppPort",
                   "Listening port for Application",
                   UintegerValue (10001),
                   MakeUintegerAccessor (&PennChord::m_appPort),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("PingTimeout",
                   "Timeout value for PING_REQ in milliseconds",
                   TimeValue (MilliSeconds (2000)),
                   MakeTimeAccessor (&PennChord::m_pingTimeout),
                   MakeTimeChecker ())

  .AddAttribute ("StabilizeTimeout",
                 "Timeout value for Stabilize in milliseconds",
                 TimeValue (MilliSeconds (1000)),
                 MakeTimeAccessor (&PennChord::m_StabilizeTimeout),
                 MakeTimeChecker ())
.AddAttribute ("KeyMonitorTimeout",
                "Timeout value for KeyMonitor  in milliseconds",
                TimeValue (MilliSeconds (1000)),
                MakeTimeAccessor (&PennChord::m_KeyMonitorTimeout),
                MakeTimeChecker ())
  ;
  return tid;
}

PennChord::PennChord ()
  : m_auditPingsTimer (Timer::CANCEL_ON_DESTROY)
{
  RandomVariable random;
  SeedManager::SetSeed (time (NULL));
  random = UniformVariable (0x00000000, 0xFFFFFFFF);
  m_currentTransactionId = random.GetInteger ();

}

PennChord::~PennChord ()
{

}

void
PennChord::DoDispose ()
{
  StopApplication ();
  PennApplication::DoDispose ();
}

void
PennChord::StartApplication (void)
{
  if (m_socket == 0)
    {
      TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
      m_socket = Socket::CreateSocket (GetNode (), tid);
      InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny(), m_appPort);
      m_socket->Bind (local);
      m_socket->SetRecvCallback (MakeCallback (&PennChord::RecvMessage, this));
    }

  // Configure timers
  m_auditPingsTimer.SetFunction (&PennChord::AuditPings, this);
  // Start timers
  m_auditPingsTimer.Schedule (m_pingTimeout);

  /*--------- new ------------*/
  m_mainAddress = ResolveNodeIpAddress(GetNode()->GetId());
  m_StabilizeTimer.SetFunction (&PennChord::SendStabReq, this);
}

void
PennChord::StopApplication (void)
{
  // Close socket
  if (m_socket)
    {
      m_socket->Close ();
      m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
      m_socket = 0;
    }

  // Cancel timers
  m_auditPingsTimer.Cancel ();

  m_pingTracker.clear ();
}


void
PennChord::SetNodeAddressMap (std::map<uint32_t, Ipv4Address> nodeAddressMap)
{
  m_nodeAddressMap = nodeAddressMap;
}

void
PennChord::SetAddressNodeMap (std::map<Ipv4Address, uint32_t> addressNodeMap)
{
  m_addressNodeMap = addressNodeMap;
}

Ipv4Address
PennChord::ResolveNodeIpAddress (uint32_t nodeNumber)
{
  std::map<uint32_t, Ipv4Address>::iterator iter = m_nodeAddressMap.find (nodeNumber);
  if (iter != m_nodeAddressMap.end ())
    {
      return iter->second;
    }
  return Ipv4Address::GetAny ();
}

std::string
PennChord::ReverseLookup (Ipv4Address ipAddress)
{
  std::map<Ipv4Address, uint32_t>::iterator iter = m_addressNodeMap.find (ipAddress);
  if (iter != m_addressNodeMap.end ())
    {
      std::ostringstream sin;
      uint32_t nodeNumber = iter->second;
      sin << nodeNumber;
      return sin.str();
    }
  return "Unknown";
}

void
PennChord::ProcessCommand (std::vector<std::string> tokens)
{
  std::vector<std::string>::iterator iterator = tokens.begin();
  std::string command = *iterator;

  if(command == "join" || command == "JOIN")
  {
	  if (tokens.size() < 2)  // xx join n
	  {
	      ERROR_LOG ("Insufficient join params...");
	      return;
	   }
	  iterator++;
	  std::istringstream sin (*iterator);
	  uint32_t nodeNumber;
	  sin >> nodeNumber;
	  std::string key = GetHash(m_mainAddress);

	  // have a criteria to see whether nodeNum is the node itself
	  if(m_addressNodeMap[m_mainAddress] != nodeNumber)
	  {


		 // Here we set the oringeNode to be the node ask for join, not the node in the chord ring
		  Ipv4Address orinNode = m_mainAddress;

		  uint32_t transactionId = GetNextTransactionId ();
		  PennChordMessage message = PennChordMessage (PennChordMessage::LOOKUP_MSG, transactionId);
		  message.SetLookupMsg(key,orinNode,"LookupReq_Join");
		  message.SetLookupMsg(ResolveNodeIpAddress(nodeNumber),"LookupReq_Join");

		  ForwardLookup(message, ResolveNodeIpAddress(nodeNumber));



	  }
	  else
	  {
		  // call create()
		  CreatRing(key);
	  }

	  m_StabilizeTimer.Schedule(m_StabilizeTimeout);
  }

  if(command == "leave" || command == "LEAVE")
  {
	  // send leave_UpdateSucc and leave_UpdatePred msg to neighbor nodes

		 if(successorIp != unknow && m_mainAddress != successorIp)
		 {
			  Ipv4Address orinNode = m_mainAddress;

			  uint32_t transactionId = GetNextTransactionId ();
			  PennChordMessage message = PennChordMessage (PennChordMessage::LOOKUP_MSG, transactionId);
			  message.SetLookupMsg(predecessorIp,"leave_UpdatePred");

			  ForwardLookup(message, successorIp);
		 }

		 if(predecessorIp != unknow && m_mainAddress != predecessorIp)
		 {
			  uint32_t transactionId = GetNextTransactionId ();
			  PennChordMessage message = PennChordMessage (PennChordMessage::LOOKUP_MSG, transactionId);
			  message.SetLookupMsg(successorIp,"leave_UpdateSucc");

			  ForwardLookup(message, predecessorIp);
		 }


	  // send its own successor and perdecessor to null
	  predecessor = "0";
	  successor = "0";
	  predecessorIp = unknow;
	  successorIp = unknow;
  }

  if(command == "ringstate" || command == "RINGSTATE")
  {
	  if(successor == "0")
	  {
		  ERROR_LOG("The node " << ReverseLookup(m_mainAddress) <<" is not in any ring!");
	  }
	  else
	  {
		 std::string currKey = GetHash(m_mainAddress);
		 CHORD_LOG("RingStateStart <currKey: " << currKey << ">: Pred< " << ReverseLookup(predecessorIp) << " ,  "
					<< predecessor  << " >" << " , Succ< "<< ReverseLookup(successorIp) << " ,  "
					<< successor  << " >");

		 if(m_mainAddress != successorIp)
		 {
			  Ipv4Address orinNode = m_mainAddress;

			  uint32_t transactionId = GetNextTransactionId ();
			  PennChordMessage message = PennChordMessage (PennChordMessage::LOOKUP_MSG, transactionId);
			  message.SetLookupMsg(GetHash(m_mainAddress),orinNode,"Ringstate");

			  ForwardLookup(message, successorIp);
		 }

	  }
  }

}

void
PennChord::SendPing (uint32_t nodeNumber, std::string pingMessage)
{
  Ipv4Address destAddress = ResolveNodeIpAddress (nodeNumber);
  if (destAddress != Ipv4Address::GetAny ())
    {
      uint32_t transactionId = GetNextTransactionId ();
      CHORD_LOG ("Sending PING_REQ to Node: " << nodeNumber << " IP: " << destAddress << " Message: " << pingMessage << " transactionId: " << transactionId);
      Ptr<PingRequest> pingRequest = Create<PingRequest> (transactionId, Simulator::Now(), destAddress, pingMessage);
      // Add to ping-tracker
      m_pingTracker.insert (std::make_pair (transactionId, pingRequest));
      Ptr<Packet> packet = Create<Packet> ();
      PennChordMessage message = PennChordMessage (PennChordMessage::PING_REQ, transactionId);
      message.SetPingReq (pingMessage);
      packet->AddHeader (message);
      m_socket->SendTo (packet, 0 , InetSocketAddress (destAddress, m_appPort));
    }
  else
    {
      // Report failure
      std::ostringstream sin;
      sin << nodeNumber;
      m_pingFailureFn (sin.str(), pingMessage);
    }
}

void
PennChord::RecvMessage (Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddr);
  InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom (sourceAddr);
  Ipv4Address sourceAddress = inetSocketAddr.GetIpv4 ();
  uint16_t sourcePort = inetSocketAddr.GetPort ();
  PennChordMessage message;
  packet->RemoveHeader (message);

  switch (message.GetMessageType ())
    {
      case PennChordMessage::PING_REQ:
        ProcessPingReq (message, sourceAddress, sourcePort);
        break;
      case PennChordMessage::PING_RSP:
        ProcessPingRsp (message, sourceAddress, sourcePort);
        break;
      case PennChordMessage::LOOKUP_MSG:
        ProcessLookupMsg (message, sourceAddress, sourcePort);
        break;
      case PennChordMessage::INVERTEDLIST_MSG:
    	processShipMsg(message);
        break;
      default:
        ERROR_LOG ("Unknown Message Type!");
        break;
    }
}

void
PennChord::ProcessPingReq (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{

    // Use reverse lookup for ease of debug
    std::string fromNode = ReverseLookup (sourceAddress);
    CHORD_LOG ("Received PING_REQ, From Node: " << fromNode << ", Message: " << message.GetPingReq().pingMessage);
    // Send Ping Response
    PennChordMessage resp = PennChordMessage (PennChordMessage::PING_RSP, message.GetTransactionId());
    resp.SetPingRsp (message.GetPingReq().pingMessage);
    Ptr<Packet> packet = Create<Packet> ();
    packet->AddHeader (resp);
    m_socket->SendTo (packet, 0 , InetSocketAddress (sourceAddress, sourcePort));
    // Send indication to application layer
    m_pingRecvFn (fromNode, message.GetPingReq().pingMessage);
}

void
PennChord::ProcessPingRsp (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  // Remove from pingTracker
  std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
  iter = m_pingTracker.find (message.GetTransactionId ());
  if (iter != m_pingTracker.end ())
    {
      std::string fromNode = ReverseLookup (sourceAddress);
      CHORD_LOG ("Received PING_RSP, From Node: " << fromNode << ", Message: " << message.GetPingRsp().pingMessage);
      m_pingTracker.erase (iter);
      // Send indication to application layer
      m_pingSuccessFn (fromNode, message.GetPingRsp().pingMessage);
    }
  else
    {
      DEBUG_LOG ("Received invalid PING_RSP!");
    }
}

/* ---------------- new -------------------*/

void
PennChord::ProcessLookupMsg (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{

     std::string fromNode = ReverseLookup (sourceAddress);
     Ipv4Address orinNode = message.GetLookupMsg().orinNode;
     std::string lookupMessage = message.GetLookupMsg().lookupMessage;

     if(lookupMessage == "LookupReq_Join" || lookupMessage == "LookupReq_Search"
    	 || lookupMessage == "LookupReq_InvertedList" )
     {
 //        PRINT_LOG ("node: " << ReverseLookup(m_mainAddress) << ", Received LOOKUP_MSG, From Node: " << fromNode << ", key: "<< key);
        //call findSuccessor function
         FindSucc(message);

     }
     if(lookupMessage == "LookupRsp_Join")
     {
    	 // after the successor is found, call join
    	 Ipv4Address resultNode = message.GetLookupMsg().resultNode;
    	 JoinRing(resultNode);

     }
     if(lookupMessage == "LookupRsp_InvertedList")
     {
    	 Ipv4Address resultNode = message.GetLookupMsg().resultNode;
    	 processInvertedRsp(resultNode,message.GetLookupMsg().key);

     }
     if(lookupMessage == "LookupRsp_JoinToEnd")
     {
    	 Ipv4Address resultNode = message.GetLookupMsg().resultNode;
    	 successorIp = resultNode;
    	 successor = GetHash(successorIp);
    	 predecessorIp = m_nodeAddressMap[m_addressNodeMap[sourceAddress]];
    	 predecessor = GetHash(predecessorIp);

   		uint32_t transactionId = GetNextTransactionId ();
   		PennChordMessage message = PennChordMessage (PennChordMessage::LOOKUP_MSG, transactionId);
   		message.SetLookupMsg(m_mainAddress,"LookupRsp_JoinChangePred");
   		ForwardLookup(message, successorIp);
   		std::string currKey = GetHash(m_mainAddress);
     }

     if(lookupMessage == "LookupRsp_JoinChangePred")
     {

    	 Ipv4Address resultNode = message.GetLookupMsg().resultNode;
    	 predecessorIp = resultNode;
    	 predecessor = GetHash(predecessorIp);

     }

     if(lookupMessage == "LookupRsp_Search")
     {
    	 // return Ip of the node to search layer,basically invoke the callback function

     }
     if(lookupMessage == "Stable_Req")
     {
    	 // return predecessor
    	 uint32_t transactionId = GetNextTransactionId ();
    	 PennChordMessage message = PennChordMessage (PennChordMessage::LOOKUP_MSG, transactionId);
    	 message.SetLookupMsg(predecessorIp,"Stable_Rsp");
    	 ForwardLookup(message, sourceAddress);
     }
     if(lookupMessage == "Stable_Rsp")
     {
    	 //receive the predecessor, call stabilization
    	 Ipv4Address ip = message.GetLookupMsg().resultNode;
    	 Stabilize(ip);

     }
     if(lookupMessage == "Notify_Msg")
     {
    	 //call notify function
    	 Ipv4Address node = m_nodeAddressMap[m_addressNodeMap[sourceAddress]];
    	 Notify(node);
     }
     if(lookupMessage == "Ringstate")
     {
    	 std::string currKey = GetHash(m_mainAddress);


    	 if(orinNode != successorIp)
    	 {
        	 CHORD_LOG("RingState <currKey: " << currKey << ">: Pred< " << ReverseLookup(predecessorIp) << " ,  "
        	    		<< predecessor  << " >" << " , Succ< "<< ReverseLookup(successorIp) << " ,  "
        	    		<< successor  << " >");
    		 ForwardLookup(message, successorIp);
    	 }
    	 else
    	 {
        	 CHORD_LOG("RingStateEnd <currKey: " << currKey << ">: Pred< " << ReverseLookup(predecessorIp) << " ,  "
        	    		<< predecessor  << " >" << " , Succ< "<< ReverseLookup(successorIp) << " ,  "
        	    		<< successor  << " >");
    	 }
     }
     if(lookupMessage == "leave_UpdateSucc")
     {
    	 successorIp = message.GetLookupMsg().resultNode;
    	 successor = GetHash(successorIp);
     }
     if(lookupMessage == "leave_UpdatePred")
     {
    	 predecessorIp = message.GetLookupMsg().resultNode;
    	 predecessor = GetHash(predecessorIp);
     }

}


void
PennChord::AuditPings ()
{
  std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
  for (iter = m_pingTracker.begin () ; iter != m_pingTracker.end();)
    {
      Ptr<PingRequest> pingRequest = iter->second;
      if (pingRequest->GetTimestamp().GetMilliSeconds() + m_pingTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
        {
          DEBUG_LOG ("Ping expired. Message: " << pingRequest->GetPingMessage () << " Timestamp: " << pingRequest->GetTimestamp().GetMilliSeconds () << " CurrentTime: " << Simulator::Now().GetMilliSeconds ());
          // Remove stale entries
          m_pingTracker.erase (iter++);
          // Send indication to application layer
          m_pingFailureFn (ReverseLookup (pingRequest->GetDestinationAddress()), pingRequest->GetPingMessage ());
        }
      else
        {
          ++iter;
        }
    }
  // Rechedule timer
  m_auditPingsTimer.Schedule (m_pingTimeout);
}

uint32_t
PennChord::GetNextTransactionId ()
{
  return m_currentTransactionId++;
}

void
PennChord::StopChord ()
{
  StopApplication ();
}

void
PennChord::SetPingSuccessCallback (Callback <void, std::string, std::string> pingSuccessFn)
{
  m_pingSuccessFn = pingSuccessFn;
}


void
PennChord::SetPingFailureCallback (Callback <void, std::string, std::string> pingFailureFn)
{
  m_pingFailureFn = pingFailureFn;
}

void
PennChord::SetPingRecvCallback (Callback <void, std::string, std::string> pingRecvFn)
{
  m_pingRecvFn = pingRecvFn;
}

/* ------------------------------ new methods ------------------------*/
void
PennChord::ForwardLookup(PennChordMessage message, Ipv4Address destAddress)
{
    Ptr<Packet> packet = Create<Packet> ();
    packet->AddHeader (message);
    m_socket->SendTo (packet, 0 , InetSocketAddress (destAddress, m_appPort));
    std::string lookupMessage = message.GetLookupMsg().lookupMessage;


    if(lookupMessage == "LookupReq_Join" || lookupMessage == "LookupReq_Search")
    {
    	std::string msgHead;
    	msgHead = (message.GetLookupMsg().orinNode == m_mainAddress) ? "LookupIssue" : "LookupRequest";
		CHORD_LOG(msgHead << " <currKey:" << GetHash(m_mainAddress) << "> : NextHop<nextAddr: "
				<< ReverseLookup(destAddress) << " , nestKey: "
				<< GetHash(destAddress) << " , TargetKey: " << message.GetLookupMsg().key << ">");

    }
}
std::string
PennChord::GetHash(std::string str)
{
	unsigned char temp[21];
	SHA1 (reinterpret_cast<const unsigned char*>(str.c_str()), str.length() , temp);
	std::stringstream s;
	for(int i=0;i<20;i++)
	{
		char buff[1];
		sprintf(buff,"%x",temp[i]);
		s << buff;
	}

	std::string result = s.str();
	if(result.length() <40)
	{
		int len = 40 - result.length();
		while(len > 0)
		{
			result = '0' + result;
			len--;
		}
	}
	return result;
}

std::string
PennChord::GetHash(Ipv4Address ip)
{
	std::ostringstream sin;
	sin << ip;
	std::string str = sin.str();

	unsigned char temp[21];
	SHA1 (reinterpret_cast<const unsigned char*>(str.c_str()), str.length() , temp);
	std::stringstream s;
	for(int i=0;i<20;i++)
	{
		char buff[1];
		sprintf(buff,"%x",temp[i]);
		s << buff;
	}

	std::string result = s.str();
	if(result.length() <40)
	{
		int len = 40 - result.length();
		while(len > 0)
		{
			result = '0' + result;
			len--;
		}
	}
	return result;
}

void
PennChord::CreatRing(std::string nodeKey)
{
	predecessor = "0";
	successor = nodeKey;

	successorIp = m_mainAddress;

	if(predecessor == "0")
		PRINT_LOG("node " << ReverseLookup(m_mainAddress) << " create a new ring!");
}
void
PennChord::JoinRing(Ipv4Address resultNode)
{
	predecessor = "0";

	successor = GetHash(resultNode);
	successorIp = resultNode;
}

void
PennChord::FindSucc(PennChordMessage message)
{
	Ipv4Address orinNode = message.GetLookupMsg().orinNode;
	std::string key = message.GetLookupMsg().key;
	std::string currKey = GetHash(m_mainAddress);
	std::string lookupMessage = message.GetLookupMsg().lookupMessage;

	// only one node in the ring
	if(successor == currKey)
	{
		LookupRsp(m_mainAddress,orinNode,key,lookupMessage);
	}
	else if((key > currKey && key < successor)) // between current node and next node,
	{
		LookupRsp(successorIp,orinNode,key,lookupMessage);
	}
	else if( ((key > currKey && key > successor) || (key < currKey && key < successor))
			&& (currKey > successor)) // reach the last node, insert directly
	{
	    if(lookupMessage == "LookupReq_Join")
	    {
			uint32_t transactionId = GetNextTransactionId ();
			PennChordMessage message = PennChordMessage (PennChordMessage::LOOKUP_MSG, transactionId);
			message.SetLookupMsg(successorIp,"LookupRsp_JoinToEnd");
			ForwardLookup(message, orinNode);
			std::string currKey = GetHash(m_mainAddress);

			successor = key;
			successorIp = orinNode;


			CHORD_LOG("LookupResult <currKey: " << currKey << ", TargetKey: " << key << " , originatorNode "
					<< ReverseLookup(orinNode)  << " >");
	    }
	    else if(lookupMessage == "LookupReq_Search")
	    {
	    	LookupRsp(successorIp,orinNode,key,lookupMessage);
			CHORD_LOG("LookupResult <currKey: " << currKey << ", TargetKey: " << key << " , originatorNode "
					<< ReverseLookup(orinNode)  << " >");
	    }
	    else if(lookupMessage == "LookupReq_InvertedList")
	    {
	    	LookupRsp(successorIp,orinNode,key,lookupMessage);
	    }

	}
	else
	{
		ForwardLookup(message, successorIp);
	}
}
void
PennChord::LookupRsp(Ipv4Address resultNode,Ipv4Address orinNode,
		std::string key,std::string lookupMessage)
{
	std::string msg;
	uint32_t transactionId = GetNextTransactionId ();
	PennChordMessage message = PennChordMessage (PennChordMessage::LOOKUP_MSG, transactionId);

    if(lookupMessage == "LookupReq_Join")
    {
    	std::string currKey = GetHash(m_mainAddress);
		CHORD_LOG("LookupResult <currKey: " << currKey << ", TargetKey: " << key << " , originatorNode "
				<< ReverseLookup(orinNode)  << " >");
		msg = "LookupRsp_Join";

    }
    else if(lookupMessage == "LookupReq_InvertedList")
    {
    	msg = "LookupRsp_InvertedList";
    	message.SetLookupMsg(key,orinNode,msg);
    }
    else if(lookupMessage == "LookupReq_Search")
    {
    	std::string currKey = GetHash(m_mainAddress);
		CHORD_LOG("LookupResult <currKey: " << currKey << ", TargetKey: " << key << " , originatorNode "
				<< ReverseLookup(orinNode)  << " >");
		msg = "LookupRsp_Search";
		message.SetLookupMsg(key,orinNode,msg);
    }

	message.SetLookupMsg(resultNode,msg);

	ForwardLookup(message, orinNode);
}

void
PennChord::SendStabReq()
{
	uint32_t transactionId = GetNextTransactionId ();
	PennChordMessage message = PennChordMessage (PennChordMessage::LOOKUP_MSG, transactionId);
	message.SetLookupMsg("Stable_Req");

	ForwardLookup(message, successorIp);
}
void
PennChord::Stabilize(Ipv4Address predecessorIp)
{
	Ipv4Address unknow;
	std::string preKey = GetHash(predecessorIp);
	std::string currKey = GetHash(m_mainAddress);
	if( ((preKey > currKey && preKey < successor) || (currKey == successor)) && preKey != GetHash(unknow))
	{
		successor = preKey;
		successorIp = predecessorIp;
	}

	if(successorIp != m_mainAddress)
	{
		uint32_t transactionId = GetNextTransactionId ();
		PennChordMessage message = PennChordMessage (PennChordMessage::LOOKUP_MSG, transactionId);
		message.SetLookupMsg("Notify_Msg");

		ForwardLookup(message, successorIp);
	}

	m_StabilizeTimer.Schedule(m_StabilizeTimeout);
}
void
PennChord::Notify(Ipv4Address node){
	std::string key = GetHash(node);
	std::string currKey = GetHash(m_mainAddress);

	if(predecessor == "0" || (key > predecessor &&  key < currKey) )
	{
		predecessor = key;
		predecessorIp = node;
	}

}

/*----------------------------------------new methods for milestone2----------------------------*/
void
PennChord::processPublish(std::string fileName){

	std::ifstream topgen;
	topgen.open (fileName.c_str());

	//setTimer to call keyMonitor(), which will wait till all the keyword to be ready
	m_KeyMonitorTimer.SetFunction (&PennChord::keyMonitor, this);
	m_KeyMonitorTimer.Schedule (m_KeyMonitorTimeout);

	std::string line;
	if(topgen.is_open())
	{
		while(topgen.good())
		{
			std::getline (topgen,line);
			std::vector<std::string> key_tokens;
			Tokenize (line, key_tokens, " ");

			// for each (keyword, docID) pair, call buildInvertedList(keyword,docID)
			if(key_tokens.size()>0)
			{
				std::string docID = key_tokens[0];
				for(uint16_t i=1;i<key_tokens.size();i++)
					buildInvertedList(key_tokens[i],docID);

			}
		}
	}

	// when finish read file, call InvertedListLookup()
	InvertedListLookup();
}

void
PennChord::buildInvertedList(std::string keyword, std::string docID){

	keyMonitorMap[keyword] = false;
	//if (!invertedIndex.containKey(keyword)), add new entry
	// else , append the docID to the vector

	std::map<std::string, std::vector<std::string> > ::const_iterator it =
		invertedList.find (keyword);

	std::vector<std::string> temp;
	if (it != invertedList.end ())
	{
		temp = it->second;
	}
	temp.push_back(docID);
	invertedList[keyword] = temp;

	CHORD_LOG("Publish <" << keyword << " , " << docID << ">");

}
void
PennChord::InvertedListLookup(){
	// for each entry in the invertedIndex, find its successor by generating
	// a lookupReq_invertedList msg
	for(std::map<std::string, std::vector<std::string> >::const_iterator
			it = invertedList.begin(); it != invertedList.end();it++)
	{
		std::string key = GetHash(it->first);
		hashedValueToOrin[key] = it->first;
		uint32_t transactionId = GetNextTransactionId ();
		PennChordMessage message = PennChordMessage (PennChordMessage::LOOKUP_MSG, transactionId);
		message.SetLookupMsg(key,m_mainAddress,"LookupReq_InvertedList");
		message.SetLookupMsg(m_mainAddress,"LookupReq_InvertedList");

		ForwardLookup(message, successorIp);
	}


}
void
PennChord::shipInvertedList(){

	// ship shipMap
	for(std::map<Ipv4Address, std::map<std::string, std::vector<std::string> > >
		::const_iterator it = shipMap.begin();it != shipMap.end();it++)
	{
		uint32_t transactionId = GetNextTransactionId ();
		PennChordMessage message = PennChordMessage (PennChordMessage::INVERTEDLIST_MSG,
				transactionId);
		message.SetInvertedListMsg(it->second,"ShipMsg_InvertedList");
		Ptr<Packet> packet = Create<Packet> ();
		packet->AddHeader(message);
		m_socket->SendTo (packet, 0 , InetSocketAddress (it->first, m_appPort));

	}

}
void
PennChord::keyMonitor(){

	bool flag = true;
	// if all keys are ready , call shipInvertedList
	for(std::map<std::string, bool >::const_iterator itera = keyMonitorMap.begin ();
		             itera != keyMonitorMap.end (); itera++)
	{
		if(!itera->second)
		{
			flag = false;
			break;
		}
	}
	if(flag && keyMonitorMap.size()!=0)
		shipInvertedList();
	else
		m_KeyMonitorTimer.Schedule (m_KeyMonitorTimeout);

}
void
PennChord::processInvertedRsp(Ipv4Address resultNode,std::string key){

	// when it receives the response, modify shipMap, keyMonitorMap, delete entry of invertedList if necessary
	std::string keyword = hashedValueToOrin[key];
	keyMonitorMap[keyword] = true;

	std::map<Ipv4Address, std::map<std::string, std::vector<std::string> > >
		::const_iterator it = shipMap.find (resultNode);

	std::map<std::string, std::vector<std::string> > temp;
	if (it != shipMap.end ())
	{
		temp = it->second;
	}
	temp[keyword] = invertedList[keyword];
	shipMap[resultNode] = temp;

	if(resultNode != m_mainAddress)
	{
		invertedList.erase(keyword);
	}
	else
	{
		std::vector<std::string> docIDsTemp = invertedList[keyword];
		for(uint16_t i=0;i<docIDsTemp.size();i++)
		{
			CHORD_LOG("Store <" << keyword << " , " << docIDsTemp[i] << ">");
		}
	}

}
void
PennChord::processShipMsg(PennChordMessage message){

	// when it receives the ship msg, update invertedList
	std::map<std::string, std::vector<std::string> > temp =
		message.GetInvertedListMsg().invertedList;

	for(std::map<std::string, std::vector<std::string> > ::const_iterator
			it = temp.begin();it != temp.end();it++)
	{
		std::string keyword = it->first;
		std::vector<std::string> docIDsToStore = it->second;

		std::map<std::string, std::vector<std::string> > ::const_iterator itera =
			invertedList.find (keyword);

		std::vector<std::string> docIDsTemp;
		if (itera != invertedList.end ())
		{
			docIDsTemp = itera->second;
		}
		for(uint16_t i=0;i<docIDsToStore.size();i++)
		{
			docIDsTemp.push_back(docIDsToStore[i]);
			CHORD_LOG("Store <" << keyword << " , " << docIDsToStore[i] << " >" << ", hashed value: " << GetHash(keyword));
		}

		invertedList[keyword] = docIDsTemp;
	}

}

void
PennChord::Tokenize(const std::string& str,
    std::vector<std::string>& tokens,
    const std::string& delimiters)
{
  // Skip delimiters at beginning.
  std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);
  // Find first "non-delimiter".
  std::string::size_type pos = str.find_first_of(delimiters, lastPos);

  while (std::string::npos != pos || std::string::npos != lastPos)
  {
    // Found a token, add it to the vector.
    tokens.push_back(str.substr(lastPos, pos - lastPos));
    // Skip delimiters.  Note the "not_of"
    lastPos = str.find_first_not_of(delimiters, pos);
    // Find next "non-delimiter"
    pos = str.find_first_of(delimiters, lastPos);
  }
}

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


#include "penn-search.h"

#include "ns3/random-variable.h"
#include "ns3/inet-socket-address.h"
#include <iostream>
#include <ios>
#include <sstream>
#include <openssl/sha.h>
#include <stdio.h>
#include <fstream>



using namespace ns3;

TypeId
PennSearch::GetTypeId ()
{
  static TypeId tid = TypeId ("PennSearch")
    .SetParent<PennApplication> ()
    .AddConstructor<PennSearch> ()
    .AddAttribute ("AppPort",
                   "Listening port for Application",
                   UintegerValue (10000),
                   MakeUintegerAccessor (&PennSearch::m_appPort),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("ChordPort",
                   "Listening port for Application",
                   UintegerValue (10001),
                   MakeUintegerAccessor (&PennSearch::m_chordPort),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("PingTimeout",
                   "Timeout value for PING_REQ in milliseconds",
                   TimeValue (MilliSeconds (2000)),
                   MakeTimeAccessor (&PennSearch::m_pingTimeout),
                   MakeTimeChecker ())
    ;
  return tid;
}

PennSearch::PennSearch ()
  : m_auditPingsTimer (Timer::CANCEL_ON_DESTROY)
{
  m_chord = NULL;
  RandomVariable random;
  SeedManager::SetSeed (time (NULL));
  random = UniformVariable (0x00000000, 0xFFFFFFFF);
  m_currentTransactionId = random.GetInteger ();
}

PennSearch::~PennSearch ()
{

}

void
PennSearch::DoDispose ()
{
  StopApplication ();
  PennApplication::DoDispose ();
}

void
PennSearch::StartApplication (void)
{
  // Create and Configure PennChord
  ObjectFactory factory;
  factory.SetTypeId (PennChord::GetTypeId ());
  factory.Set ("AppPort", UintegerValue (m_chordPort));
  m_chord = factory.Create<PennChord> ();
  m_chord->SetNode (GetNode ());
  m_chord->SetNodeAddressMap (m_nodeAddressMap);
  m_chord->SetAddressNodeMap (m_addressNodeMap);
  m_chord->SetModuleName ("CHORD");
  std::string nodeId = GetNodeId ();
  m_chord->SetNodeId (nodeId);

  // Configure Callbacks with Chord
  m_chord->SetPingSuccessCallback (MakeCallback (&PennSearch::HandleChordPingSuccess, this));
  m_chord->SetPingFailureCallback (MakeCallback (&PennSearch::HandleChordPingFailure, this));
  m_chord->SetPingRecvCallback (MakeCallback (&PennSearch::HandleChordPingRecv, this));
  // Start Chord
  m_chord->SetStartTime (Simulator::Now());
  m_chord->Start ();
  if (m_socket == 0)
    {
      TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
      m_socket = Socket::CreateSocket (GetNode (), tid);
      InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny(), m_appPort);
      m_socket->Bind (local);
      m_socket->SetRecvCallback (MakeCallback (&PennSearch::RecvMessage, this));
    }

  // Configure timers
  m_auditPingsTimer.SetFunction (&PennSearch::AuditPings, this);
  // Start timers
  m_auditPingsTimer.Schedule (m_pingTimeout);
}

void
PennSearch::StopApplication (void)
{
  //Stop chord
  m_chord->StopChord ();
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
PennSearch::SetNodeAddressMap (std::map<uint32_t, Ipv4Address> nodeAddressMap)
{
  m_nodeAddressMap = nodeAddressMap;
}

void
PennSearch::SetAddressNodeMap (std::map<Ipv4Address, uint32_t> addressNodeMap)
{
  m_addressNodeMap = addressNodeMap;
}

Ipv4Address
PennSearch::ResolveNodeIpAddress (uint32_t nodeNumber)
{
  std::map<uint32_t, Ipv4Address>::iterator iter = m_nodeAddressMap.find (nodeNumber);
  if (iter != m_nodeAddressMap.end ())
    {
      return iter->second;
    }
  return Ipv4Address::GetAny ();
}

std::string
PennSearch::ReverseLookup (Ipv4Address ipAddress)
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
PennSearch::ProcessCommand (std::vector<std::string> tokens)
{
  std::vector<std::string>::iterator iterator = tokens.begin();
  std::string command = *iterator;
  if (command == "CHORD")
    {
      // Send to Chord Sub-Layer
      tokens.erase (iterator);
      m_chord->ProcessCommand (tokens);
    }
  if (command == "PING")
    {
      if (tokens.size() < 3)
        {
          ERROR_LOG ("Insufficient PING params...");
          return;
        }
      iterator++;
      if (*iterator != "*")
        {
          std::istringstream sin (*iterator);
          uint32_t nodeNumber;
          sin >> nodeNumber;
          iterator++;
          std::string pingMessage = *iterator;
          SendPing (nodeNumber, pingMessage);
        }
      else
        {
          iterator++;
          std::string pingMessage = *iterator;
          std::map<uint32_t, Ipv4Address>::iterator iter;
          for (iter = m_nodeAddressMap.begin () ; iter != m_nodeAddressMap.end (); iter++)
            {
              SendPing (iter->first, pingMessage);
            }
        }
    }
  if (command == "PUBLISH")
    {
	  if (tokens.size() < 2)
	          {
	            ERROR_LOG ("Insufficient PUBLISH params...");
	            return;
	          }
	  iterator++;
	  std::istringstream sin (*iterator);
	  std::string fileName;
	  sin >> fileName;
	  m_chord->processPublish(fileName);
    }
  if(command == "TEST")
  {

	  test();

  }
}

void
PennSearch::SendPing (uint32_t nodeNumber, std::string pingMessage)
{
  // Send Ping Via-Chord layer
  SEARCH_LOG ("Sending Ping via Chord Layer to node: " << nodeNumber << " Message: " << pingMessage);
  m_chord->SendPing (nodeNumber, pingMessage);
}

void
PennSearch::SendPennSearchPing (uint32_t nodeNumber, std::string pingMessage)
{
  Ipv4Address destAddress = ResolveNodeIpAddress (nodeNumber);
  if (destAddress != Ipv4Address::GetAny ())
    {
      uint32_t transactionId = GetNextTransactionId ();
      SEARCH_LOG ("Sending PING_REQ to Node: " << nodeNumber << " IP: " << destAddress << " Message: " << pingMessage << " transactionId: " << transactionId);
      Ptr<PingRequest> pingRequest = Create<PingRequest> (transactionId, Simulator::Now(), destAddress, pingMessage);
      // Add to ping-tracker
      m_pingTracker.insert (std::make_pair (transactionId, pingRequest));
      Ptr<Packet> packet = Create<Packet> ();
      PennSearchMessage message = PennSearchMessage (PennSearchMessage::PING_REQ, transactionId);
      message.SetPingReq (pingMessage);
      packet->AddHeader (message);
      m_socket->SendTo (packet, 0 , InetSocketAddress (destAddress, m_appPort));
    }


}

void
PennSearch::RecvMessage (Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddr);
  InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom (sourceAddr);
  Ipv4Address sourceAddress = inetSocketAddr.GetIpv4 ();
  uint16_t sourcePort = inetSocketAddr.GetPort ();
  PennSearchMessage message;
  packet->RemoveHeader (message);

  switch (message.GetMessageType ())
    {
      case PennSearchMessage::PING_REQ:
        ProcessPingReq (message, sourceAddress, sourcePort);
        break;
      case PennSearchMessage::PING_RSP:
        ProcessPingRsp (message, sourceAddress, sourcePort);
        break;
      default:
        ERROR_LOG ("Unknown Message Type!");
        break;
    }
}

void
PennSearch::ProcessPingReq (PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{

    // Use reverse lookup for ease of debug
    std::string fromNode = ReverseLookup (sourceAddress);
    SEARCH_LOG ("Received PING_REQ, From Node: " << fromNode << ", Message: " << message.GetPingReq().pingMessage);
    // Send Ping Response
    PennSearchMessage resp = PennSearchMessage (PennSearchMessage::PING_RSP, message.GetTransactionId());
    resp.SetPingRsp (message.GetPingReq().pingMessage);
    Ptr<Packet> packet = Create<Packet> ();
    packet->AddHeader (resp);
    m_socket->SendTo (packet, 0 , InetSocketAddress (sourceAddress, sourcePort));
}

void
PennSearch::ProcessPingRsp (PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  // Remove from pingTracker
  std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
  iter = m_pingTracker.find (message.GetTransactionId ());
  if (iter != m_pingTracker.end ())
    {
      std::string fromNode = ReverseLookup (sourceAddress);
      SEARCH_LOG ("Received PING_RSP, From Node: " << fromNode << ", Message: " << message.GetPingRsp().pingMessage);
      m_pingTracker.erase (iter);
    }
  else
    {
      DEBUG_LOG ("Received invalid PING_RSP!");
    }
}

void
PennSearch::AuditPings ()
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
PennSearch::GetNextTransactionId ()
{
  return m_currentTransactionId++;
}

// Handle Chord Callbacks

void
PennSearch::HandleChordPingFailure (std::string nodeId, std::string message)
{
  SEARCH_LOG ("Chord Ping Expired! Destination nodeId: " << nodeId << " Message: " << message);
}

void
PennSearch::HandleChordPingSuccess (std::string nodeId, std::string message)
{
  SEARCH_LOG ("Chord Ping Success! Destination nodeId: " << nodeId << " Message: " << message);
  // Send ping via search layer
  std::istringstream sin (nodeId);
  uint32_t nodeNumber;
  sin >> nodeNumber;
  SendPennSearchPing (nodeNumber, message);
}

void
PennSearch::HandleChordPingRecv (std::string nodeId, std::string message)
{
  SEARCH_LOG ("Chord Layer Received Ping! Source nodeId: " << nodeId << " Message: " << message);
}

// Override PennLog

void
PennSearch::SetTrafficVerbose (bool on)
{
  m_chord->SetTrafficVerbose (on);
  g_trafficVerbose = on;
}

void
PennSearch::SetErrorVerbose (bool on)
{
  m_chord->SetErrorVerbose (on);
  g_errorVerbose = on;
}

void
PennSearch::SetDebugVerbose (bool on)
{
  m_chord->SetDebugVerbose (on);
  g_debugVerbose = on;
}

void
PennSearch::SetStatusVerbose (bool on)
{
  m_chord->SetStatusVerbose (on);
  g_statusVerbose = on;
}

void
PennSearch::SetChordVerbose (bool on)
{
  m_chord->SetChordVerbose (on);
  g_chordVerbose = on;
}

void
PennSearch::SetSearchVerbose (bool on)
{
  m_chord->SetSearchVerbose (on);
  g_searchVerbose = on;
}

/* ------------------------ new ------------------------*/
uint64_t
PennSearch::GetHash(std::string str)
{
    std::locale loc;
	const std::collate<char>& coll = std::use_facet<std::collate<char> >(loc);
	return coll.hash(str.data(),str.data()+str.length());
}



void
PennSearch::test()
{

	for(std::map<std::string, std::vector<std::string> > ::const_iterator
			it = m_chord->invertedList.begin();it != m_chord->invertedList.end();it++)
	{
		std::string keyword = it->first;
		std::vector<std::string> docIDsToStore = it->second;

		for(uint16_t i=0;i<docIDsToStore.size();i++)
		{
			PRINT_LOG("Test Store <" << keyword << " , " << docIDsToStore[i] << " >" << ", hashed value: " << GetHash(keyword));
		}
	}
}























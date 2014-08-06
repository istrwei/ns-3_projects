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


#include "ns3/dv-routing-protocol.h"
#include "ns3/socket-factory.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/random-variable.h"
#include "ns3/inet-socket-address.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-route.h"
#include "ns3/uinteger.h"
#include <sys/time.h>


using namespace ns3;

#define INFI 99999

NS_LOG_COMPONENT_DEFINE ("DVRoutingProtocol");
NS_OBJECT_ENSURE_REGISTERED (DVRoutingProtocol);

TypeId
DVRoutingProtocol::GetTypeId (void)
{
  static TypeId tid = TypeId ("DVRoutingProtocol")
  .SetParent<PennRoutingProtocol> ()
  .AddConstructor<DVRoutingProtocol> ()
  .AddAttribute ("DVPort",
                 "Listening port for DV packets",
                 UintegerValue (6000),
                 MakeUintegerAccessor (&DVRoutingProtocol::m_dvPort),
                 MakeUintegerChecker<uint16_t> ())
  .AddAttribute ("PingTimeout",
                 "Timeout value for PING_REQ in milliseconds",
                 TimeValue (MilliSeconds (2000)),
                 MakeTimeAccessor (&DVRoutingProtocol::m_pingTimeout),
                 MakeTimeChecker ())
  .AddAttribute ("MaxTTL",
                 "Maximum TTL value for DV packets",
                 UintegerValue (16),
                 MakeUintegerAccessor (&DVRoutingProtocol::m_maxTTL),
                 MakeUintegerChecker<uint8_t> ())
  .AddAttribute ("NdiscTimeout",
               "Timeout value for neighbor discover in milliseconds",
               TimeValue (MilliSeconds (10000)),
               MakeTimeAccessor (&DVRoutingProtocol::m_ndiscTimeout),
               MakeTimeChecker ())
  .AddAttribute ("CheckNeighborTimeout",
             "Timeout value for neighbor discover in milliseconds",
             TimeValue (MilliSeconds (10000)),
             MakeTimeAccessor (&DVRoutingProtocol::m_checkNeighborTimeout),
             MakeTimeChecker ())
  .AddAttribute ("dvBrocastTimeout",
         "Timeout value for neighbor discover in milliseconds",
         TimeValue (MilliSeconds (1000)),
         MakeTimeAccessor (&DVRoutingProtocol::m_dvBrocastTimeout),
         MakeTimeChecker ())
  .AddAttribute ("dvTimeout",
           "Timeout value for neighbor discover in milliseconds",
           TimeValue (MilliSeconds (500)),
           MakeTimeAccessor (&DVRoutingProtocol::m_dvTimeout),
           MakeTimeChecker ())


  ;
  return tid;
}

DVRoutingProtocol::DVRoutingProtocol ()
  : m_auditPingsTimer (Timer::CANCEL_ON_DESTROY)
{
  RandomVariable random;
  SeedManager::SetSeed (time (NULL));
  random = UniformVariable (0x00000000, 0xFFFFFFFF);
  m_currentSequenceNumber = random.GetInteger ();
  // Setup static routing
  m_staticRouting = Create<Ipv4StaticRouting> ();
}

DVRoutingProtocol::~DVRoutingProtocol ()
{
}

void
DVRoutingProtocol::DoDispose ()
{
  // Close sockets
  for (std::map< Ptr<Socket>, Ipv4InterfaceAddress >::iterator iter = m_socketAddresses.begin ();
       iter != m_socketAddresses.end (); iter++)
    {
      iter->first->Close ();
    }
  m_socketAddresses.clear ();

  // Clear static routing
  m_staticRouting = 0;

  // Cancel timers
  m_auditPingsTimer.Cancel ();
  m_ndiscTimer.Cancel();
  m_checkNeighborTimer.Cancel();
  m_dvBrocastTimer.Cancel();
  m_dvTimer.Cancel();

  m_pingTracker.clear ();

  PennRoutingProtocol::DoDispose ();
}

void
DVRoutingProtocol::SetMainInterface (uint32_t mainInterface)
{
  m_mainAddress = m_ipv4->GetAddress (mainInterface, 0).GetLocal ();
}

void
DVRoutingProtocol::SetNodeAddressMap (std::map<uint32_t, Ipv4Address> nodeAddressMap)
{
  m_nodeAddressMap = nodeAddressMap;
}

void
DVRoutingProtocol::SetAddressNodeMap (std::map<Ipv4Address, uint32_t> addressNodeMap)
{
  m_addressNodeMap = addressNodeMap;
}

Ipv4Address
DVRoutingProtocol::ResolveNodeIpAddress (uint32_t nodeNumber)
{
  std::map<uint32_t, Ipv4Address>::iterator iter = m_nodeAddressMap.find (nodeNumber);
  if (iter != m_nodeAddressMap.end ())
    {
      return iter->second;
    }
  return Ipv4Address::GetAny ();
}

std::string
DVRoutingProtocol::ReverseLookup (Ipv4Address ipAddress)
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
DVRoutingProtocol::DoStart ()
{
  // Create sockets
  for (uint32_t i = 0 ; i < m_ipv4->GetNInterfaces () ; i++)
    {
      Ipv4Address ipAddress = m_ipv4->GetAddress (i, 0).GetLocal ();
      if (ipAddress == Ipv4Address::GetLoopback ())
        continue;
      // Create socket on this interface
      Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),
          UdpSocketFactory::GetTypeId ());
      socket->SetAllowBroadcast (true);
      InetSocketAddress inetAddr (m_ipv4->GetAddress (i, 0).GetLocal (), m_dvPort);
      socket->SetRecvCallback (MakeCallback (&DVRoutingProtocol::RecvDVMessage, this));
      if (socket->Bind (inetAddr))
        {
          NS_FATAL_ERROR ("DVRoutingProtocol::DoStart::Failed to bind socket!");
        }
      Ptr<NetDevice> netDevice = m_ipv4->GetNetDevice (i);
      socket->BindToNetDevice (netDevice);
      m_socketAddresses[socket] = m_ipv4->GetAddress (i, 0);
    }
  // Configure timers
  m_auditPingsTimer.SetFunction (&DVRoutingProtocol::AuditPings, this);
   m_ndiscTimer.SetFunction (&DVRoutingProtocol::NeighborDiscover, this);
  m_checkNeighborTimer.SetFunction (&DVRoutingProtocol::CheckNeighbors, this);
  m_dvTimer.SetFunction (&DVRoutingProtocol::DvCompute, this);
  m_dvBrocastTimer.SetFunction (&DVRoutingProtocol::BrocastDV, this);

  // Start timers
  m_auditPingsTimer.Schedule (m_pingTimeout);
  m_ndiscTimer.Schedule(m_ndiscTimeout);
  m_checkNeighborTimer.Schedule(m_checkNeighborTimeout);
  m_dvTimer.Schedule(m_dvTimeout);
  m_dvBrocastTimer.Schedule(m_dvBrocastTimeout);

  //

  DvEntry &entryDv = m_DvTable[m_mainAddress];
  entryDv.next = m_mainAddress;
  entryDv.cost = 0;
  entryDv.count = 0;

}

Ptr<Ipv4Route>
DVRoutingProtocol::RouteOutput (Ptr<Packet> packet, const Ipv4Header &header, Ptr<NetDevice> outInterface, Socket::SocketErrno &sockerr)
{

		Ptr<Ipv4Route> rtentry;
		DvEntry entry;
		bool found = false;

		if (Lookup (header.GetDestination (), entry) && entry.cost != INFI && entry.next != m_mainAddress)
		{
		      uint32_t interfaceIdx = m_ipv4->GetInterfaceForAddress
								  (m_table.find(entry.next)->second.interfaceAddr);
		      if(m_table.find(entry.next) == m_table.end())
				PRINT_LOG("NEXT NOT FOUND!!!!");
		      if (outInterface && m_ipv4->GetInterfaceForDevice (outInterface) != static_cast<int> (interfaceIdx))
		        {
		          // We do not attempt to perform a constrained routing search
		          // if the caller specifies the oif; we just enforce that
		          // that the found route matches the requested outbound interface
		          DEBUG_LOG ( " RouteOutput for dest=" << ReverseLookup (header.GetDestination ())
		                        << " Route interface " << interfaceIdx
		                        << " does not match requested output interface "
		                        << m_ipv4->GetInterfaceForDevice (outInterface));
		          sockerr = Socket::ERROR_NOROUTETOHOST;
		          return rtentry;
		        }
		      rtentry = Create<Ipv4Route> ();
		      rtentry->SetDestination (header.GetDestination ());
		      // the source address is the interface address that matches
		      // the destination address (when multiple are present on the
		      // outgoing interface, one is selected via scoping rules)
		      NS_ASSERT (m_ipv4);
		      uint32_t numOifAddresses = m_ipv4->GetNAddresses (interfaceIdx);
		      NS_ASSERT (numOifAddresses > 0);
		      Ipv4InterfaceAddress ifAddr;
		      if (numOifAddresses == 1) {
		        ifAddr = m_ipv4->GetAddress (interfaceIdx, 0);
		      } else {
		        DEBUG_LOG ("XXX Not implemented yet:  IP aliasing");
		      }
		      rtentry->SetSource (m_mainAddress);
		      rtentry->SetGateway (entry.next);
		      rtentry->SetOutputDevice (m_ipv4->GetNetDevice (interfaceIdx));
		      sockerr = Socket::ERROR_NOTERROR;
		      DEBUG_LOG ("RouteOutput for dest " << ReverseLookup (header.GetDestination ())
		                    << " --> nextHop = " << ReverseLookup (entry.next)
		                    << " interface=" << m_table.find(entry.next)->second.interfaceAddr);
		      found = true;
		    }
		  else
		    {
		      rtentry = m_staticRouting->RouteOutput (packet, header, outInterface, sockerr);

		      if (rtentry)
		        {
		          found = true;
		          DEBUG_LOG ("Found route to: " << ReverseLookup (rtentry->GetDestination ()) << " via next-hop: " << ReverseLookup (rtentry->GetGateway ())
		        		  << " with source: " << rtentry->GetSource () << " and output device " << rtentry->GetOutputDevice());
		        }
		    }

		  if (!found)
		    {
			  DEBUG_LOG ("No Route to destination: " << header.GetDestination ());
		      sockerr = Socket::ERROR_NOROUTETOHOST;
		    }
		  return rtentry;
}

bool
DVRoutingProtocol::RouteInput  (Ptr<const Packet> packet,
  const Ipv4Header &header, Ptr<const NetDevice> inputDev,
  UnicastForwardCallback ucb, MulticastForwardCallback mcb,
  LocalDeliverCallback lcb, ErrorCallback ecb)
{


	Ipv4Address destinationAddress = header.GetDestination ();

	  Ipv4Address sourceAddress = header.GetSource ();

	  // Drop if packet was originated by this node
	  if (IsOwnAddress (sourceAddress) == true)
	    {
	      return true;
	    }

	  // Check for local delivery
	  uint32_t interfaceNum = m_ipv4->GetInterfaceForDevice (inputDev);
	  if (m_ipv4->IsDestinationAddress (destinationAddress, interfaceNum))
	    {
	      if (!lcb.IsNull ())
	        {
	          lcb (packet, header, interfaceNum);
	          return true;
	        }
	      else
	        {
	          return false;
	        }
	    }

	  // Forwarding
	  Ptr<Ipv4Route> rtentry;
	  DvEntry entry;
	  if (Lookup (header.GetDestination (), entry) && entry.cost != INFI)
	    {
	      rtentry = Create<Ipv4Route> ();
	      rtentry->SetDestination (header.GetDestination ());
	      uint32_t interfaceIdx = m_ipv4->GetInterfaceForAddress
								  (m_table.find(entry.next)->second.interfaceAddr);

	      NS_ASSERT (m_ipv4);
	      uint32_t numOifAddresses = m_ipv4->GetNAddresses (interfaceIdx);
	      NS_ASSERT (numOifAddresses > 0);
	      Ipv4InterfaceAddress ifAddr;
	      if (numOifAddresses == 1) {
	        ifAddr = m_ipv4->GetAddress (interfaceIdx, 0);
	      } else {
	    	  DEBUG_LOG ("XXX Not implemented yet:  IP aliasing and OLSR");
	      }
	      rtentry->SetSource (m_mainAddress);
	      rtentry->SetGateway (entry.next);
	      rtentry->SetOutputDevice (m_ipv4->GetNetDevice (interfaceIdx));

	      DEBUG_LOG (" RouteInput for dest = " << ReverseLookup (header.GetDestination ())
	                    << " --> nextHop = " << ReverseLookup (entry.next)
	                    << " interface=" << m_table.find(entry.next)->second.interfaceAddr);

	      ucb (rtentry, packet, header);
	      return true;
	    }
	  else
	    {
		  if (m_staticRouting->RouteInput (packet, header, inputDev, ucb, mcb, lcb, ecb))
		    {
		      DEBUG_LOG (" Local deliver for dest = ");
		      return true;
		    }
	      else
	        {
	    	  DEBUG_LOG ("Cannot forward packet. No Route to destination: " << header.GetDestination ());
	          return false;
	        }
	    }
}

void
DVRoutingProtocol::BroadcastPacket (Ptr<Packet> packet)
{
  for (std::map<Ptr<Socket> , Ipv4InterfaceAddress>::const_iterator i =
      m_socketAddresses.begin (); i != m_socketAddresses.end (); i++)
    {
      Ipv4Address broadcastAddr = i->second.GetLocal ().GetSubnetDirectedBroadcast (i->second.GetMask ());
      i->first->SendTo (packet, 0, InetSocketAddress (broadcastAddr, m_dvPort));

  }
}

void
DVRoutingProtocol::ProcessCommand (std::vector<std::string> tokens)
{
  std::vector<std::string>::iterator iterator = tokens.begin();
  std::string command = *iterator;
  if (command == "PING")
    {
      if (tokens.size() < 3)
        {
          ERROR_LOG ("Insufficient PING params...");
          return;
        }
      iterator++;
      std::istringstream sin (*iterator);
      uint32_t nodeNumber;
      sin >> nodeNumber;
      iterator++;
      std::string pingMessage = *iterator;
      Ipv4Address destAddress = ResolveNodeIpAddress (nodeNumber);
      if (destAddress != Ipv4Address::GetAny ())
        {
          uint32_t sequenceNumber = GetNextSequenceNumber ();
          TRAFFIC_LOG ("Sending PING_REQ to Node: " << nodeNumber << " IP: " << destAddress << " Message: " << pingMessage << " SequenceNumber: " << sequenceNumber);
          Ptr<PingRequest> pingRequest = Create<PingRequest> (sequenceNumber, Simulator::Now(), destAddress, pingMessage);
          // Add to ping-tracker
          m_pingTracker.insert (std::make_pair (sequenceNumber, pingRequest));
          Ptr<Packet> packet = Create<Packet> ();
          DVMessage dvMessage = DVMessage (DVMessage::PING_REQ, sequenceNumber, m_maxTTL, m_mainAddress);
          dvMessage.SetPingReq (destAddress, pingMessage);
          packet->AddHeader (dvMessage);
          BroadcastPacket (packet);

        }
    }
  else if (command == "DUMP")
    {
      if (tokens.size() < 2)
        {
          ERROR_LOG ("Insufficient Parameters!");
          return;
        }
      iterator++;
      std::string table = *iterator;
      if (table == "ROUTES" || table == "ROUTING")
        {
          DumpRoutingTable ();
        }
      else if (table == "NEIGHBORS" || table == "NEIGHBOURS")
        {
          DumpNeighbors ();
        }
	   else if (table == "LSA")
        {
          DumpLSA ();
        }
    }
}

void
DVRoutingProtocol::DumpLSA ()
{
  STATUS_LOG (std::endl << "**************** LSA DUMP ********************" << std::endl
              << "Node\t\tNeighbor(s)");
	 for(std::map<Ipv4Address, NeighborTableEntry>::const_iterator itera = m_table.begin ();
	             itera != m_table.end (); itera++)
	  {
	     PRINT_LOG ("\t" << itera->second.nodeNum << "\t\t" << itera->first << "\t\t" << itera->second.interfaceAddr);
	  }
}

void
DVRoutingProtocol::DumpNeighbors ()
{
  STATUS_LOG (std::endl << "**************** Neighbor List ********************" << std::endl
              << "Node Number\t\tNode Address\t\tInterface");

  DumpTable();
}

void
DVRoutingProtocol::DumpRoutingTable ()
{
 STATUS_LOG (std::endl << "********************************** Route Table **********************************************" << std::endl
             << "DestNumber\t\tDestAddr\t\tNextHopNumber\t\tNextHopAddr\t\tInterface\t\tCost");  PRINT_LOG ("");


for(std::map<Ipv4Address, DvEntry> ::const_iterator itera = m_DvTable.begin ();
         		             itera != m_DvTable.end (); itera++)
{
	std::map<Ipv4Address, NeighborTableEntry>::iterator it = m_table.find(itera->second.next);

	Ipv4Address interface;
	if(it == m_table.end())
		interface = Ipv4Address("0.0.0.0");
	else
		interface = it->second.interfaceAddr;


	PRINT_LOG("   " << ReverseLookup(itera->first) << " \t\t\t " << itera->first << " \t\t\t " << ReverseLookup(itera->second.next)
			<< " \t\t " << itera->second.next << "\t\t " << interface
			<< "\t\t " << itera->second.cost);
}

}
void
DVRoutingProtocol::RecvDVMessage (Ptr<Socket> socket)
{

  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddr);
  InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom (sourceAddr);
  Ipv4Address sourceAddress = inetSocketAddr.GetIpv4 ();
  DVMessage dvMessage;
  packet->RemoveHeader (dvMessage);

  switch (dvMessage.GetMessageType ())
    {
      case DVMessage::PING_REQ:
        ProcessPingReq (dvMessage);
        break;
      case DVMessage::PING_RSP:
        ProcessPingRsp (dvMessage);
        break;

      //neighbor discover
      case DVMessage::NDISC_REQ:
         ProcessNdiscReq (dvMessage);
         break;
      case DVMessage::NDISC_RSP:
         ProcessNdiscRsp (dvMessage,socket);
         break;

      case DVMessage::DV:
         ProcessDV (dvMessage);
         break;

      default:
        ERROR_LOG ("Unknown Message Type!");
        break;
    }
}

void
DVRoutingProtocol::ProcessPingReq (DVMessage dvMessage)
{
  // Check destination address
  if (IsOwnAddress (dvMessage.GetPingReq().destinationAddress))
    {
      // Use reverse lookup for ease of debug
      std::string fromNode = ReverseLookup (dvMessage.GetOriginatorAddress ());
      TRAFFIC_LOG ("Received PING_REQ, From Node: " << fromNode << ", Message: " << dvMessage.GetPingReq().pingMessage);
      // Send Ping Response
      DVMessage dvResp = DVMessage (DVMessage::PING_RSP, dvMessage.GetSequenceNumber(), m_maxTTL, m_mainAddress);
      dvResp.SetPingRsp (dvMessage.GetOriginatorAddress(), dvMessage.GetPingReq().pingMessage);
      Ptr<Packet> packet = Create<Packet> ();
      packet->AddHeader (dvResp);
      BroadcastPacket (packet);
    }
}

void
DVRoutingProtocol::ProcessPingRsp (DVMessage dvMessage)
{
  // Check destination address
  if (IsOwnAddress (dvMessage.GetPingRsp().destinationAddress))
    {
      // Remove from pingTracker
      std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
      iter = m_pingTracker.find (dvMessage.GetSequenceNumber ());
      if (iter != m_pingTracker.end ())
        {
          std::string fromNode = ReverseLookup (dvMessage.GetOriginatorAddress ());
          TRAFFIC_LOG ("Received PING_RSP, From Node: " << fromNode << ", Message: " << dvMessage.GetPingRsp().pingMessage);
          m_pingTracker.erase (iter);
        }
      else
        {
          DEBUG_LOG ("Received invalid PING_RSP!");
        }
    }
}

/* ----------------------------------------- neighbor discover  ----------------------------------------------*/

void
DVRoutingProtocol::ProcessNdiscReq (DVMessage dvMessage)
{
	std::string fromNode = ReverseLookup (dvMessage.GetOriginatorAddress ());
	std::string nodeNum = ReverseLookup (m_mainAddress);

	DVMessage dvResp = DVMessage (DVMessage::NDISC_RSP, dvMessage.GetSequenceNumber(), 1 , m_mainAddress);
	dvResp.SetNdiscRsp (dvMessage.GetOriginatorAddress(), dvMessage.GetNdiscReq().helloMessage);
	Ptr<Packet> packet = Create<Packet> ();
	packet->AddHeader (dvResp);
	BroadcastPacket (packet);
}

void
DVRoutingProtocol::ProcessNdiscRsp (DVMessage dvMessage, Ptr<Socket> socket)
{
	if (IsOwnAddress (dvMessage.GetNdiscRsp().destinationAddress))
	{
		std::string fromNode = ReverseLookup (dvMessage.GetOriginatorAddress ());
		std::string nodeNum = ReverseLookup (m_mainAddress);

		std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator it =
			m_socketAddresses.find (socket);

		uint32_t interfaceNum;

		Ipv4InterfaceAddress interfaceAddr = it->second;
		Ipv4Address localAddr = interfaceAddr.GetLocal();
		interfaceNum = m_ipv4->GetInterfaceForAddress(localAddr);

		AddEntry (dvMessage.GetOriginatorAddress (),interfaceNum,fromNode,localAddr);
	}
}

void
DVRoutingProtocol::NeighborDiscover ()
{
	std::string nodeNum = ReverseLookup (m_mainAddress);

	std::string helloMessage = "hello neighbor";
	uint32_t sequenceNumber = GetNextSequenceNumber ();

	Ptr<Packet> packet = Create<Packet> ();
	DVMessage dvMessage = DVMessage (DVMessage::NDISC_REQ, sequenceNumber, 1 , m_mainAddress);
	dvMessage.SetNdiscReq (helloMessage);
	packet->AddHeader (dvMessage);
	BroadcastPacket (packet);

	m_ndiscTimer.Schedule (m_ndiscTimeout);
}

void
DVRoutingProtocol::AddEntry (Ipv4Address const &neighborAddr,
                        uint32_t interface,
                        std::string &nodeNum,Ipv4Address interfaceAddr )
{

  // Creates a new rt entry with specified values
  NeighborTableEntry &entry = m_table[neighborAddr];

  entry.neighborAddr = neighborAddr;
  entry.interface = interface;
  entry.nodeNum = nodeNum;
  entry.flag = true;
  entry.counter = 0;
  entry.interfaceAddr=interfaceAddr;


  // Create new Dist Vector Entry and update the local vector
  DvEntry &entryDv = m_DvTable[neighborAddr];
  entryDv.next = neighborAddr;
  entryDv.cost = 1;
  entryDv.count = 1;

}


bool
DVRoutingProtocol::Lookup (Ipv4Address const &neighborAddr,
							NeighborTableEntry &outEntry) const
{
  // Get the iterator at "dest" position
  std::map<Ipv4Address, NeighborTableEntry>::const_iterator it =
    m_table.find (neighborAddr);
  // If there is no route to "dest", return NULL
  if (it == m_table.end ())
    return false;
  outEntry = it->second;
  return true;
}

bool
DVRoutingProtocol::Lookup (Ipv4Address const &dest,
		DvEntry &outEntry) const
{
  // Get the iterator at "dest" position
  std::map<Ipv4Address, DvEntry>::const_iterator it =
	  m_DvTable.find (dest);
  // If there is no route to "dest", return NULL
  if (it == m_DvTable.end ())
    return false;
  outEntry = it->second;
  return true;
}

void
DVRoutingProtocol:: DumpTable ()
{
	 for(std::map<Ipv4Address, NeighborTableEntry>::const_iterator itera = m_table.begin ();
	             itera != m_table.end (); itera++)
	  {
	     PRINT_LOG ("\t" << itera->second.nodeNum << "\t\t" << itera->first << "\t\t" << itera->second.interfaceAddr);
	  }
}

void
DVRoutingProtocol:: CheckNeighbors()
{
	for(std::map<Ipv4Address, NeighborTableEntry>::const_iterator itera = m_table.begin ();
		             itera != m_table.end (); itera++)
	{

        if(itera->second.flag)
		{
			NeighborTableEntry &entry = m_table[itera->first];
			entry.flag = false;
			entry.counter = 0;
		}

		else
		{
			NeighborTableEntry &entry = m_table[itera->first];
			entry.counter = itera->second.counter + 1;
		}
        if(itera->second.counter == 2)
        {
        	m_table.erase (itera->first);

        	m_DvTable[itera->first].cost = INFI;
        	for(std::map<Ipv4Address, DvEntry>::iterator it = m_DvTable.begin ();
       				 it != m_DvTable.end (); it++)
        	{
        		if(it->second.next == itera->first)
        			m_DvTable[it->first].cost = INFI;
        	}
        	m_AllDvTabel.erase(itera->first);

        	DumpNeighbors ();
        }



	}
	m_checkNeighborTimer.Schedule(m_checkNeighborTimeout);
}

/* ---------------------------------------------------------------------------------------------------------*/

/* --------------------------------------------dv table---------------------------------------------------*/

void
DVRoutingProtocol::BrocastDV()
{
	std::string nodeNum = ReverseLookup (m_mainAddress);

	uint32_t sequenceNumber = GetNextSequenceNumber ();
	Ptr<Packet> packet = Create<Packet> ();
	DVMessage dvMessage = DVMessage (DVMessage::DV, sequenceNumber, 1 , m_mainAddress);
	dvMessage.SetDV (m_mainAddress, m_DvTable);
	packet->AddHeader (dvMessage);
	BroadcastPacket (packet);

	m_dvBrocastTimer.Schedule (m_dvBrocastTimeout);


}

void
DVRoutingProtocol::ProcessDV (DVMessage dvMessage)
{
	std::map<Ipv4Address, DvEntry> DvTable = dvMessage.GetDV().DvTable;
	Ipv4Address senderAddr = dvMessage.GetOriginatorAddress();
	std::string senderNodeNum = ReverseLookup(senderAddr);        // node number of the sender
	std::string nodeNum = ReverseLookup (m_mainAddress);

	m_AllDvTabel[senderAddr] = DvTable;


	m_dvTimer.Cancel();
	m_dvTimer.Schedule(m_dvTimeout);

}

void
DVRoutingProtocol::DvCompute ()
{
	bool insert;

	std::string nodeNum = ReverseLookup (m_mainAddress);


	/*----------------------- update the cost, where the path remains the same --------------------------------*/


	 for(std::map<Ipv4Address, DvEntry>::iterator it = m_DvTable.begin ();
				 it != m_DvTable.end (); it++)
	  {
		 // check every next hop
		 Ipv4Address nextHop = it->second.next;
		 Ipv4Address destNode = it->first;

		 // find the vector of the next hop
		 std::map<Ipv4Address, std::map<Ipv4Address, DvEntry> >::iterator itera = m_AllDvTabel.find(nextHop);

		 // if the next hop is not itself
		 if(nextHop != m_mainAddress && itera != m_AllDvTabel.end())
		 {

			 //find the cost from next hop to original dest
			 std::map<Ipv4Address, DvEntry>::iterator itVector = itera->second.find(destNode);


			 if(it->second.cost != m_DvTable.find(nextHop)->second.cost + itVector->second.cost)
			 {
					if(m_DvTable[destNode].count>16)
					{
						m_DvTable[destNode].cost = INFI;
					}
					else
					{
					 m_DvTable[it->first].lastCost = m_DvTable.find(nextHop)->second.cost + itVector->second.cost;
					 m_DvTable[it->first].cost = m_DvTable.find(nextHop)->second.cost + itVector->second.cost;
					 m_DvTable[it->first].count = 1 + itVector->second.count;
					}
			 }

		 }

	  }

    /*---------------------------update dist vector, find potential shorter path --------------------------*/

		 // for every node in the big map(not include the local node itself),
		for(std::map<Ipv4Address, std::map<Ipv4Address, DvEntry> >::iterator itera =m_AllDvTabel.begin();
								itera != m_AllDvTabel.end(); itera++)
	        {
				Ipv4Address nextHop = itera->first;

				std::map<Ipv4Address, DvEntry> DistVector = itera->second;

					// check the destination in every dist vector in the big map
					 for(std::map<Ipv4Address, DvEntry>::iterator itVector = DistVector.begin ();
								 itVector != DistVector.end (); itVector++)
					  {
						 Ipv4Address destNode= itVector->first;

						 // if there is not path in the local vector to some dest node
						if(m_DvTable.find(destNode)== m_DvTable.end())
						{
							insert=true;
						}
						else
						{
							insert=false;
						}


						if(insert)
						{
							m_DvTable[destNode].next = nextHop;
							m_DvTable[destNode].cost=((m_DvTable[nextHop].cost+itVector->second.cost) > INFI) ? INFI
									:(m_DvTable[nextHop].cost+itVector->second.cost);
							m_DvTable[destNode].count=itVector->second.count+1;

						}
						else
						{

							if(m_DvTable.find(destNode)->second.cost >  (m_DvTable[nextHop].cost + itVector->second.cost) )
							{
								if(m_DvTable[destNode].count>16 && (m_DvTable[destNode].lastCost < (m_DvTable[nextHop].cost + itVector->second.cost)))
								{
									m_DvTable[destNode].cost = INFI;
								}
								else
								{
									m_DvTable[destNode].next = nextHop;
									m_DvTable[destNode].lastCost = m_DvTable[nextHop].cost+itVector->second.cost;
									m_DvTable[destNode].cost = m_DvTable[nextHop].cost+itVector->second.cost;
									m_DvTable[destNode].count = itVector->second.count+1;
								}

							}

						}

					  }

	        }
}


/* ---------------------------------------------------------------------------------------------------------*/
bool
DVRoutingProtocol::IsOwnAddress (Ipv4Address originatorAddress)
{
  // Check all interfaces
  for (std::map<Ptr<Socket> , Ipv4InterfaceAddress>::const_iterator i = m_socketAddresses.begin (); i != m_socketAddresses.end (); i++)
    {
      Ipv4InterfaceAddress interfaceAddr = i->second;
      if (originatorAddress == interfaceAddr.GetLocal ())
        {
          return true;
        }
    }
  return false;

}

void
DVRoutingProtocol::AuditPings ()
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
DVRoutingProtocol::GetNextSequenceNumber ()
{
  return m_currentSequenceNumber++;
}

void
DVRoutingProtocol::NotifyInterfaceUp (uint32_t i)
{
  m_staticRouting->NotifyInterfaceUp (i);
}
void
DVRoutingProtocol::NotifyInterfaceDown (uint32_t i)
{
  m_staticRouting->NotifyInterfaceDown (i);
}
void
DVRoutingProtocol::NotifyAddAddress (uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyAddAddress (interface, address);
}
void
DVRoutingProtocol::NotifyRemoveAddress (uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyRemoveAddress (interface, address);
}

void
DVRoutingProtocol::SetIpv4 (Ptr<Ipv4> ipv4)
{
  m_ipv4 = ipv4;
  m_staticRouting->SetIpv4 (m_ipv4);
}

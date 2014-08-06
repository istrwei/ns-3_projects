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


#include "ns3/ls-routing-protocol.h"
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

NS_LOG_COMPONENT_DEFINE ("LSRoutingProtocol");
NS_OBJECT_ENSURE_REGISTERED (LSRoutingProtocol);

TypeId
LSRoutingProtocol::GetTypeId (void)
{
  static TypeId tid = TypeId ("LSRoutingProtocol")
  .SetParent<PennRoutingProtocol> ()
  .AddConstructor<LSRoutingProtocol> ()
  .AddAttribute ("LSPort",
                 "Listening port for LS packets",
                 UintegerValue (5000),
                 MakeUintegerAccessor (&LSRoutingProtocol::m_lsPort),
                 MakeUintegerChecker<uint16_t> ())
  .AddAttribute ("PingTimeout",
                 "Timeout value for PING_REQ in milliseconds",
                 TimeValue (MilliSeconds (2000)),
                 MakeTimeAccessor (&LSRoutingProtocol::m_pingTimeout),
                 MakeTimeChecker ())
  .AddAttribute ("MaxTTL",
                 "Maximum TTL value for LS packets",
                 UintegerValue (16),
                 MakeUintegerAccessor (&LSRoutingProtocol::m_maxTTL),
                 MakeUintegerChecker<uint8_t> ())
  .AddAttribute ("NdiscTimeout",
               "Timeout value for neighbor discover in milliseconds",
               TimeValue (MilliSeconds (10000)),
               MakeTimeAccessor (&LSRoutingProtocol::m_ndiscTimeout),
               MakeTimeChecker ())
  .AddAttribute ("CheckNeighborTimeout",
             "Timeout value for neighbor discover in milliseconds",
             TimeValue (MilliSeconds (10000)),
             MakeTimeAccessor (&LSRoutingProtocol::m_checkNeighborTimeout),
             MakeTimeChecker ())
   .AddAttribute ("lspTimeout",
           "Timeout value for neighbor discover in milliseconds",
           TimeValue (MilliSeconds (5000)),
           MakeTimeAccessor (&LSRoutingProtocol::m_lspTimeout),
           MakeTimeChecker ())

  ;
  return tid;
}

LSRoutingProtocol::LSRoutingProtocol ()
  : m_auditPingsTimer (Timer::CANCEL_ON_DESTROY)
{
  RandomVariable random;
  SeedManager::SetSeed (time (NULL));
  random = UniformVariable (0x00000000, 0xFFFFFFFF);
  m_currentSequenceNumber = random.GetInteger ();
  // Setup static routing
  m_staticRouting = Create<Ipv4StaticRouting> ();
}

LSRoutingProtocol::~LSRoutingProtocol ()
{
}

void
LSRoutingProtocol::DoDispose ()
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
  m_lspTimer.Cancel();

  m_pingTracker.clear ();

  PennRoutingProtocol::DoDispose ();
}

void
LSRoutingProtocol::SetMainInterface (uint32_t mainInterface)
{
  m_mainAddress = m_ipv4->GetAddress (mainInterface, 0).GetLocal ();
}

void
LSRoutingProtocol::SetNodeAddressMap (std::map<uint32_t, Ipv4Address> nodeAddressMap)
{
  m_nodeAddressMap = nodeAddressMap;
}

void
LSRoutingProtocol::SetAddressNodeMap (std::map<Ipv4Address, uint32_t> addressNodeMap)
{
  m_addressNodeMap = addressNodeMap;
}

Ipv4Address
LSRoutingProtocol::ResolveNodeIpAddress (uint32_t nodeNumber)
{
  std::map<uint32_t, Ipv4Address>::iterator iter = m_nodeAddressMap.find (nodeNumber);
  if (iter != m_nodeAddressMap.end ())
    {
      return iter->second;
    }
  return Ipv4Address::GetAny ();
}

std::string
LSRoutingProtocol::ReverseLookup (Ipv4Address ipAddress)
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
LSRoutingProtocol::DoStart ()
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
      InetSocketAddress inetAddr (m_ipv4->GetAddress (i, 0).GetLocal (), m_lsPort);
      socket->SetRecvCallback (MakeCallback (&LSRoutingProtocol::RecvLSMessage, this));
      if (socket->Bind (inetAddr))
        {
          NS_FATAL_ERROR ("LSRoutingProtocol::DoStart::Failed to bind socket!");
        }
      Ptr<NetDevice> netDevice = m_ipv4->GetNetDevice (i);
      socket->BindToNetDevice (netDevice);
      m_socketAddresses[socket] = m_ipv4->GetAddress (i, 0);
    }
  // Configure timers
  m_auditPingsTimer.SetFunction (&LSRoutingProtocol::AuditPings, this);
  m_ndiscTimer.SetFunction (&LSRoutingProtocol::NeighborDiscover, this);
  m_checkNeighborTimer.SetFunction (&LSRoutingProtocol::CheckNeighbors, this);
  m_lspTimer.SetFunction (&LSRoutingProtocol::LspDijk, this);
  m_lspFloodTimer.SetFunction (&LSRoutingProtocol::NewEntry, this);


  // Start timers
  m_auditPingsTimer.Schedule (m_pingTimeout);
  m_ndiscTimer.Schedule(m_ndiscTimeout);
  m_checkNeighborTimer.Schedule(m_checkNeighborTimeout);

}

Ptr<Ipv4Route>
LSRoutingProtocol::RouteOutput (Ptr<Packet> packet, const Ipv4Header &header, Ptr<NetDevice> outInterface, Socket::SocketErrno &sockerr)
{

	Ptr<Ipv4Route> rtentry;
	RouteTableEntry entry;
	bool found = false;

	if (Lookup (header.GetDestination (), entry) && entry.nextHopAddr != m_mainAddress)
	{
	      uint32_t interfaceIdx = m_ipv4->GetInterfaceForAddress(entry.interfaceAddr);
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
	      rtentry->SetGateway (entry.nextHopAddr);
	      rtentry->SetOutputDevice (m_ipv4->GetNetDevice (interfaceIdx));
	      sockerr = Socket::ERROR_NOTERROR;
	      DEBUG_LOG ("RouteOutput for dest " << ReverseLookup (header.GetDestination ())
	                    << " --> nextHop = " << ReverseLookup (entry.nextHopAddr)
	                    << " interface=" << entry.interfaceAddr);
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
LSRoutingProtocol::RouteInput  (Ptr<const Packet> packet,
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
  RouteTableEntry entry;
  if (Lookup (header.GetDestination (), entry))
    {
      rtentry = Create<Ipv4Route> ();
      rtentry->SetDestination (header.GetDestination ());
      uint32_t interfaceIdx = m_ipv4->GetInterfaceForAddress(entry.interfaceAddr);

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
      rtentry->SetGateway (entry.nextHopAddr);
      rtentry->SetOutputDevice (m_ipv4->GetNetDevice (interfaceIdx));

      DEBUG_LOG (" RouteInput for dest = " << ReverseLookup (header.GetDestination ())
                    << " --> nextHop = " << ReverseLookup (entry.nextHopAddr)
                    << " interface=" << entry.interfaceAddr);

      ucb (rtentry, packet, header);
      return true;
    }
  else
    {
	  if (m_staticRouting->RouteInput (packet, header, inputDev, ucb, mcb, lcb, ecb))
	    {
		  PRINT_LOG("ROUTEINPUT   NODE " << ReverseLookup(m_mainAddress) << "  ROUTINPUT STATIC CALLED");
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
LSRoutingProtocol::BroadcastPacket (Ptr<Packet> packet)
{
  for (std::map<Ptr<Socket> , Ipv4InterfaceAddress>::const_iterator i =
      m_socketAddresses.begin (); i != m_socketAddresses.end (); i++)
    {
      Ipv4Address broadcastAddr = i->second.GetLocal ().GetSubnetDirectedBroadcast (i->second.GetMask ());
      i->first->SendTo (packet, 0, InetSocketAddress (broadcastAddr, m_lsPort));

    }
}

void
LSRoutingProtocol::ProcessCommand (std::vector<std::string> tokens)
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
          LSMessage lsMessage = LSMessage (LSMessage::PING_REQ, sequenceNumber, m_maxTTL, m_mainAddress);
          lsMessage.SetPingReq (destAddress, pingMessage);
          packet->AddHeader (lsMessage);
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
LSRoutingProtocol::DumpLSA ()
{
  STATUS_LOG (std::endl << "**************** LSA DUMP ********************" << std::endl
              << "Node\t\tNeighbor(s)");
  PRINT_LOG ("");
}

void
LSRoutingProtocol::DumpNeighbors ()
{
  STATUS_LOG (std::endl << "**************** Neighbor List ********************" << std::endl
             << "Node Number\t\tNode Address\t\tInterface");

  DumpTable();
}

void
LSRoutingProtocol::DumpRoutingTable ()
{
 STATUS_LOG (std::endl << "********************************** Route Table **********************************************" << std::endl
             << "DestNumber DestAddr\t NextHopNumber NextHopAddr\tInterface\tCost");  PRINT_LOG ("");
 for(std::map<Ipv4Address, RouteTableEntry>::const_iterator itera = m_RouteTable.begin ();
        	 itera != m_RouteTable.end (); itera++)
{
     PRINT_LOG ("      " << itera->second.destNum << "   " << itera->first << " \t\t " << itera->second.nextHopNum
    		 << "      " << itera->second.nextHopAddr << " \t " << itera->second.interfaceAddr << " \t " << itera->second.cost);
}

}
void
LSRoutingProtocol::RecvLSMessage (Ptr<Socket> socket)
{

  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddr);
  InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom (sourceAddr);
  Ipv4Address sourceAddress = inetSocketAddr.GetIpv4 ();
  LSMessage lsMessage;
  packet->RemoveHeader (lsMessage);

  switch (lsMessage.GetMessageType ())
    {
      case LSMessage::PING_REQ:
        ProcessPingReq (lsMessage);
        break;
      case LSMessage::PING_RSP:
        ProcessPingRsp (lsMessage);
        break;

      //neighbor discover
      case LSMessage::NDISC_REQ:
         ProcessNdiscReq (lsMessage);
         break;
      case LSMessage::NDISC_RSP:
         ProcessNdiscRsp (lsMessage,socket);
         break;


      case LSMessage::LSP:
         ProcessLsp(lsMessage);
         break;

      default:
        ERROR_LOG ("Unknown Message Type!");
        break;
    }
}

void
LSRoutingProtocol::ProcessPingReq (LSMessage lsMessage)
{
  // Check destination address
  if (IsOwnAddress (lsMessage.GetPingReq().destinationAddress))
    {
      // Use reverse lookup for ease of debug
      std::string fromNode = ReverseLookup (lsMessage.GetOriginatorAddress ());
      TRAFFIC_LOG ("Received PING_REQ, From Node: " << fromNode << ", Message: " << lsMessage.GetPingReq().pingMessage);
      // Send Ping Response
      LSMessage lsResp = LSMessage (LSMessage::PING_RSP, lsMessage.GetSequenceNumber(), m_maxTTL, m_mainAddress);
      lsResp.SetPingRsp (lsMessage.GetOriginatorAddress(), lsMessage.GetPingReq().pingMessage);
      Ptr<Packet> packet = Create<Packet> ();
      packet->AddHeader (lsResp);
      BroadcastPacket (packet);
    }
}

void
LSRoutingProtocol::ProcessPingRsp (LSMessage lsMessage)
{
  // Check destination address
  if (IsOwnAddress (lsMessage.GetPingRsp().destinationAddress))
    {
      // Remove from pingTracker
      std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
      iter = m_pingTracker.find (lsMessage.GetSequenceNumber ());
      if (iter != m_pingTracker.end ())
        {
          std::string fromNode = ReverseLookup (lsMessage.GetOriginatorAddress ());
          TRAFFIC_LOG ("Received PING_RSP, From Node: " << fromNode << ", Message: " << lsMessage.GetPingRsp().pingMessage);
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
LSRoutingProtocol::ProcessNdiscReq (LSMessage lsMessage)
{

	std::string fromNode = ReverseLookup (lsMessage.GetOriginatorAddress ());
	std::string nodeNum = ReverseLookup (m_mainAddress);

	LSMessage lsResp = LSMessage (LSMessage::NDISC_RSP, lsMessage.GetSequenceNumber(), 1 , m_mainAddress);
	lsResp.SetNdiscRsp (lsMessage.GetOriginatorAddress(), lsMessage.GetNdiscReq().helloMessage);
	Ptr<Packet> packet = Create<Packet> ();
	packet->AddHeader (lsResp);
	BroadcastPacket (packet);

}

void
LSRoutingProtocol::ProcessNdiscRsp (LSMessage lsMessage, Ptr<Socket> socket)
{
	if (IsOwnAddress (lsMessage.GetNdiscRsp().destinationAddress))
	{
		std::string fromNode = ReverseLookup (lsMessage.GetOriginatorAddress ());
		std::string nodeNum = ReverseLookup (m_mainAddress);

		std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator it =
			m_socketAddresses.find (socket);

		uint32_t interfaceNum;

		Ipv4InterfaceAddress interfaceAddr = it->second;
		Ipv4Address localAddr = interfaceAddr.GetLocal();
		interfaceNum = m_ipv4->GetInterfaceForAddress(localAddr);

		if(!Lookup(lsMessage.GetOriginatorAddress ()))
		{
			m_lspFloodTimer.Cancel();
			m_lspFloodTimer.Schedule(m_lspTimeout);
		}

		AddEntry (lsMessage.GetOriginatorAddress (),interfaceNum,fromNode,localAddr);
	}
}

void
LSRoutingProtocol::NeighborDiscover ()
{
	std::string nodeNum = ReverseLookup (m_mainAddress);

	std::string helloMessage = "neighborDisc";
	uint32_t sequenceNumber = GetNextSequenceNumber ();

	Ptr<Packet> packet = Create<Packet> ();
	LSMessage lsMessage = LSMessage (LSMessage::NDISC_REQ, sequenceNumber, 1 , m_mainAddress);
	lsMessage.SetNdiscReq (helloMessage);
	packet->AddHeader (lsMessage);
	BroadcastPacket (packet);

	m_ndiscTimer.Schedule (m_ndiscTimeout);
}

void
LSRoutingProtocol::AddEntry (Ipv4Address const &neighborAddr,
                        uint32_t interface,
                        std::string &nodeNum, Ipv4Address const &interfaceAddr)
{

  // Creates a new rt entry with specified values
  NeighborTableEntry &entry = m_table[neighborAddr];

  entry.neighborAddr = neighborAddr;
  entry.interface = interface;
  entry.nodeNum = nodeNum;
  entry.flag = true;
  entry.interfaceAddr=interfaceAddr;
  entry.counter = 0;
}


bool
LSRoutingProtocol::Lookup (Ipv4Address const &neighborAddr) const
{
  // Get the iterator at "dest" position
  std::map<Ipv4Address, NeighborTableEntry>::const_iterator it =
    m_table.find (neighborAddr);
  // If there is no route to "dest", return NULL
  if (it == m_table.end ())
    return false;

  return true;
}

bool
LSRoutingProtocol::Lookup (Ipv4Address const &dest,
		RouteTableEntry &outEntry) const
{
  // Get the iterator at "dest" position
  std::map<Ipv4Address, RouteTableEntry>::const_iterator it =
	  m_RouteTable.find (dest);
  // If there is no route to "dest", return NULL
  if (it == m_RouteTable.end ())
    return false;
  outEntry = it->second;
  return true;
}

void
LSRoutingProtocol:: DumpTable ()
{
	 for(std::map<Ipv4Address, NeighborTableEntry>::const_iterator itera = m_table.begin ();
	             itera != m_table.end (); itera++)
	  {
	     PRINT_LOG ("\t" << itera->second.nodeNum << "\t\t" << itera->first << "\t\t" << itera->second.interfaceAddr);
	  }
}

void
LSRoutingProtocol:: CheckNeighbors()
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
			DumpNeighbors ();

			neighborChanged = true;

		}
	}
	if(neighborChanged)
	{
		needFlood = true;
		FloodLsp();
		neighborChanged = false;
	}
	m_checkNeighborTimer.Schedule(m_checkNeighborTimeout);
}

/* ---------------------------------------------------------------------------------------------------------*/

/* --------------------------------------------  lsp flooding ----------------------------------------------*/


void
LSRoutingProtocol::ProcessLsp(LSMessage lsMessage)
{
	std::map<Ipv4Address, NeighborTableEntry> neighborTable = lsMessage.GetLSP().neighborTable;
	Ipv4Address senderAddr = lsMessage.GetOriginatorAddress();
	std::string senderNodeNum = ReverseLookup(senderAddr);        // node number of the sender
	uint32_t timeStamp = lsMessage.GetTimeStamp();

	std::string nodeNum = ReverseLookup (m_mainAddress);

	std::map<std::string, uint32_t> ::const_iterator it =
	    lspCheck.find (senderNodeNum);

	  // If it is not in the table,store and forward it
	  if (it == lspCheck.end () || (it != lspCheck.end () && it->second != timeStamp))
	  {
		  lspCheck[senderNodeNum] = timeStamp;
		  lspTableList[senderAddr] = neighborTable;

		  //forward the packet
		  Ptr<Packet> packet = Create<Packet> ();
		  packet->AddHeader (lsMessage);
		  BroadcastPacket (packet);


		  m_lspTimer.Cancel();
		  m_lspTimer.Schedule(m_lspTimeout);

	  }

	  FloodLsp();

}

void
LSRoutingProtocol::LspDijk()
{
		needFlood = true;

		/*
		if(lspTableList.size()!=0)
			old_lspTableList = lspTableList;
		*/


		lspTableList[m_mainAddress] = m_table;

		Dijk();

		lspTableList.clear();
		lspCheck.clear();


}


void LSRoutingProtocol::Dijk()
{
    const int totalsize= lspTableList.size();
    int adjacency_matrix[totalsize][totalsize];
	int node;
    int set[lspTableList.size()];
	int num1,num2;
    int router[totalsize];
    int temp[totalsize],dis[totalsize];
    int pre;
    int size;
	Ipv4Address nodeaddress;
	int distance;
	int counter=1;
	int i,j;
	int num_nodes = totalsize;
    int src;
    std::map<int, Ipv4Address> NodeIp;
    std::map<Ipv4Address, int> Ip2NodeNum;

    std::map<Ipv4Address, std::map<Ipv4Address, NeighborTableEntry> >::const_iterator itNodeIp = lspTableList.begin ();

    for(int i=0;i<totalsize;i++)
    {
    	NodeIp[i] = itNodeIp->first;
    	Ip2NodeNum[itNodeIp->first] = i;
    	itNodeIp++;
    }


/* -----------------form the matrix ---------------------*/

        for(uint32_t i=0;i<lspTableList.size();i++)
	{
		for(uint32_t j=0;j<lspTableList.size();j++)
		{
			if(i!=j)
			adjacency_matrix[i][j]=999;
			else
			adjacency_matrix[i][j]=0;
		}
	}


        for(std::map<Ipv4Address, std::map<Ipv4Address, NeighborTableEntry> >::const_iterator it =lspTableList.begin ();
							it != lspTableList.end(); it++)
        {
			node = Ip2NodeNum[it->first];
			std::map<Ipv4Address, NeighborTableEntry> temp = it->second;

			for(std::map<Ipv4Address, NeighborTableEntry>::const_iterator it = temp.begin ();
							 it != temp.end (); it++)
			{
                int des = Ip2NodeNum[it->second.neighborAddr];
				adjacency_matrix[node][des] = (int)it->second.cost;
			}
         }

        // initialize
        for(int x=0;x<num_nodes;x++)
           {
                router[x]=-1;
                set[x]=999;
                temp[x]=-1;
                dis[x]=0;
           }
        src = Ip2NodeNum[m_mainAddress];
        set[0]= src;
        router[src] = src;
        distance=999;


 /* -----------------Dijk Algorithm -----------------*/

        if(totalsize != 0)
        {
	         while(1)

	         {
	        	 i=0;
	        	 while(1)

	        	 {
	        		 if(set[i]==999)
	        			 break;
	        		 else
	        		 	i++;

	        	 }
	        	 size=i;

	        	 for( i=0;i<size;i++)
	        	 {
	        		 for( j=0;j<num_nodes;j++)
	        		 {
	        			 if(adjacency_matrix[set[i]][j]< distance - dis[set[i]] && adjacency_matrix[set[i]][j]!=0)
	        			 {
	        				 distance = adjacency_matrix[set[i]][j]+dis[set[i]] ;
	        				 num1=set[i];
	        				 num2=j;
	        				 //	printf("node %d, dis %d \n",set[i],distance);
	        			 }

	        		 }
	        	 }


                   	dis[num2]=dis[num1]+adjacency_matrix[num1][num2];

	                set[counter]=num2;
	                 for( i=0;i<counter;i++)
	                {
	                  distance=adjacency_matrix[num2][set[i]]=adjacency_matrix[set[i]][num2]=999;
	                }

                    pre=num1;
	                if(pre == src)  // if last node is the source node, set the next hop to be current node
	                {
	                	temp[num2]=num2;
	                }

	                else
	                {
	                	temp[num2]=router[pre];
                    }
	                router[num2]=temp[num2];

	                if(size==num_nodes-1)
	                	 break;
                 counter++;
               }
        }

		m_RouteTable.clear();
	for(int t=0;t<num_nodes;t++)
	 {
		  RouteTableEntry &entry = m_RouteTable[NodeIp[t]];

		  entry.destNum = ReverseLookup(NodeIp[t]);
		  entry.nextHopAddr = NodeIp[router[t]];
		  entry.nextHopNum = ReverseLookup(NodeIp[router[t]]);
		  entry.interfaceAddr = m_table.find(NodeIp[router[t]])->second.interfaceAddr;
		  entry.cost = dis[t];
	 }
}



void
LSRoutingProtocol::FloodLsp ()
{
	if(needFlood)
	{
		std::string nodeNum = ReverseLookup (m_mainAddress);

		if(m_table.size()!=0)
			lspTableList[m_mainAddress] = m_table;

		uint32_t sequenceNumber = GetNextSequenceNumber ();
		Ptr<Packet> packet = Create<Packet> ();
		LSMessage lsMessage = LSMessage (LSMessage::LSP, sequenceNumber, 1, m_mainAddress);
		lsMessage.SetLSP (m_mainAddress, m_table);
		uint32_t timeStamp = Simulator::Now().GetMilliSeconds();

		lsMessage.SetTimeStamp(timeStamp);

		lspCheck[nodeNum] = timeStamp;

		packet->AddHeader (lsMessage);
		BroadcastPacket (packet);

		if(m_table.size()==0)
			LspDijk();
	}

		needFlood = false;

}


void
LSRoutingProtocol::NewEntry()
{
	needFlood = true;
	FloodLsp();
}


/* ---------------------------------------------------------------------------------------------------------*/


bool
LSRoutingProtocol::IsOwnAddress (Ipv4Address originatorAddress)
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
LSRoutingProtocol::AuditPings ()
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
LSRoutingProtocol::GetNextSequenceNumber ()
{
  return m_currentSequenceNumber++;
}

void
LSRoutingProtocol::NotifyInterfaceUp (uint32_t i)
{
  m_staticRouting->NotifyInterfaceUp (i);
}
void
LSRoutingProtocol::NotifyInterfaceDown (uint32_t i)
{
  m_staticRouting->NotifyInterfaceDown (i);
}
void
LSRoutingProtocol::NotifyAddAddress (uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyAddAddress (interface, address);
}
void
LSRoutingProtocol::NotifyRemoveAddress (uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyRemoveAddress (interface, address);
}

void
LSRoutingProtocol::SetIpv4 (Ptr<Ipv4> ipv4)
{
  m_ipv4 = ipv4;
  m_staticRouting->SetIpv4 (m_ipv4);
}

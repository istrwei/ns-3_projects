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

#ifndef PENN_CHORD_H
#define PENN_CHORD_H

#include "ns3/penn-application.h"
#include "ns3/penn-chord-message.h"
#include "ns3/ping-request.h"

#include "ns3/ipv4-address.h"
#include <map>
#include <set>
#include <vector>
#include <string>
#include "ns3/socket.h"
#include "ns3/nstime.h"
#include "ns3/timer.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"

using namespace ns3;

class PennChord : public PennApplication
{
  public:
    static TypeId GetTypeId (void);
    PennChord ();
    virtual ~PennChord ();

    void SendPing (uint32_t nodeNumber, std::string pingMessage);
    void RecvMessage (Ptr<Socket> socket);
    void ProcessPingReq (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
    void ProcessPingRsp (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
    void AuditPings ();
    uint32_t GetNextTransactionId ();
    void StopChord ();

    // Callback with Application Layer (add more when required)
    void SetPingSuccessCallback (Callback <void, std::string, std::string> pingSuccessFn);
    void SetPingFailureCallback (Callback <void, std::string, std::string> pingFailureFn);
    void SetPingRecvCallback (Callback <void, std::string, std::string> pingRecvFn);

    // new methods
    void ForwardLookup(PennChordMessage message, Ipv4Address destAddress);
    void ProcessLookupMsg (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
    std::string GetHash(std::string str);
    std::string GetHash(Ipv4Address ip);
    void CreatRing(std::string nodeKey);
    void JoinRing(Ipv4Address resultNode);
    void FindSucc(PennChordMessage message);
    void LookupRsp(Ipv4Address resultNode,Ipv4Address orinNode,
    		std::string key,std::string lookupMessage);
    void SendStabReq();
    void Stabilize(Ipv4Address predecessorIp);
    void Notify(Ipv4Address node);
    void processPublish(std::string fileName);
    void buildInvertedList(std::string keyword, std::string docID);
    void InvertedListLookup();
    void shipInvertedList();
    void keyMonitor();
    void processInvertedRsp(Ipv4Address resultNode,std::string key);
    void processShipMsg(PennChordMessage message);
    void Tokenize(const std::string& str, std::vector<std::string>& tokens,
        const std::string& delimiters);

public:
    std::map<std::string, std::vector<std::string> > invertedList;
    std::map<std::string, bool > keyMonitorMap;
    std::map<Ipv4Address, std::map<std::string, std::vector<std::string> > > shipMap;
    std::map<std::string, std::string > hashedValueToOrin;
    std::map<uint32_t, Ipv4Address> m_nodeAddressMap;

    // From PennApplication
    virtual void ProcessCommand (std::vector<std::string> tokens);
    virtual void SetNodeAddressMap (std::map<uint32_t, Ipv4Address> nodeAddressMap);
    virtual void SetAddressNodeMap (std::map<Ipv4Address, uint32_t> addressNodeMap);
  private:
    virtual Ipv4Address ResolveNodeIpAddress (uint32_t nodeNumber);
    virtual std::string ReverseLookup (Ipv4Address ipv4Address);

  protected:
    virtual void DoDispose ();

  private:
    virtual void StartApplication (void);
    virtual void StopApplication (void);

    uint32_t m_currentTransactionId;
    Ptr<Socket> m_socket;
    Time m_pingTimeout;
    uint16_t m_appPort;

    std::map<Ipv4Address, uint32_t> m_addressNodeMap;
    // Timers
    Timer m_auditPingsTimer;
    // Ping tracker
    std::map<uint32_t, Ptr<PingRequest> > m_pingTracker;
    // Callbacks
    Callback <void, std::string, std::string> m_pingSuccessFn;
    Callback <void, std::string, std::string> m_pingFailureFn;
    Callback <void, std::string, std::string> m_pingRecvFn;

    /*---- new ----*/
    std::string predecessor;
    std::string successor;
    Ipv4Address predecessorIp;
    Ipv4Address successorIp;
    Ipv4Address unknow;

    Ipv4Address m_mainAddress;

    Timer m_StabilizeTimer;
    Time m_StabilizeTimeout;
    Timer m_KeyMonitorTimer;
    Time m_KeyMonitorTimeout;

    /*---------------- new variable ----------------*/



};

#endif



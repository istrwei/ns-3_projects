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

#ifndef LS_MESSAGE_H
#define LS_MESSAGE_H

#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include "ns3/packet.h"
#include "ns3/object.h"
#include <map>

using namespace ns3;

#define IPV4_ADDRESS_SIZE 4



struct NeighborTableEntry
{
  Ipv4Address neighborAddr;	///< Address of the destination node.
  uint32_t interface; ///< Interface index
  std::string nodeNum;
  uint32_t counter;
  Ipv4Address interfaceAddr;
  bool flag ;
  uint32_t cost;

  NeighborTableEntry () : // default values
	  neighborAddr (),
    interface (0), nodeNum (),counter(0), interfaceAddr(), flag(false), cost(1){};
};

class LSMessage : public Header
{
  public:
    LSMessage ();
    virtual ~LSMessage ();


    enum MessageType
      {
        PING_REQ = 1,
        PING_RSP = 2,

        // extra message types
        NDISC_REQ = 3,
        NDISC_RSP = 4,

        LSP = 5,


      };

    LSMessage (LSMessage::MessageType messageType, uint32_t sequenceNumber, uint8_t ttl, Ipv4Address originatorAddress);

    /**
    *  \brief Sets message type
    *  \param messageType message type
    */
    void SetMessageType (MessageType messageType);

    /**
     *  \returns message type
     */
    MessageType GetMessageType () const;

    /**
     *  \brief Sets Sequence Number
     *  \param sequenceNumber Sequence Number of the request
     */
    void SetSequenceNumber (uint32_t sequenceNumber);

    /**
     *  \returns Sequence Number
     */
    uint32_t GetSequenceNumber () const;

    /**
     *  \brief Sets Originator IP Address
     *  \param originatorAddress Originator IPV4 address
     */
    void SetOriginatorAddress (Ipv4Address originatorAddress);

    /**
     *  \returns Originator IPV4 address
     */
    Ipv4Address GetOriginatorAddress () const;

    /**
     *  \brief Sets Time To Live of the message
     *  \param ttl TTL of the message
     */
    void SetTTL (uint8_t ttl);

    /**
     *  \returns TTL of the message
     */
    uint8_t GetTTL () const;

  private:
    /**
     *  \cond
     */
    MessageType m_messageType;
    uint32_t m_sequenceNumber;
    Ipv4Address m_originatorAddress;
    uint8_t m_ttl;
    /**
     *  \endcond
     */
  public:
    static TypeId GetTypeId (void);
    virtual TypeId GetInstanceTypeId (void) const;
    void Print (std::ostream &os) const;
    uint32_t GetSerializedSize (void) const;
    void Serialize (Buffer::Iterator start) const;
    uint32_t Deserialize (Buffer::Iterator start);


    struct PingReq
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address destinationAddress;
        std::string pingMessage;
      };

    struct PingRsp
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address destinationAddress;
        std::string pingMessage;
      };

    struct NDISC_Req
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        std::string helloMessage;
      };

    struct NDISC_Rsp
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        // Payload
        Ipv4Address destinationAddress;
        std::string helloMessage;
      };

    // LSP message



    struct LSP_msg
      {
        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);

        // Payload
        Ipv4Address nodeAddress;
        std::map<Ipv4Address, NeighborTableEntry> neighborTable;
        uint32_t timeStamp;

      };


    /////////////////////////////////////////////////////////////////////////

  private:
    struct
      {
        PingReq pingReq;
        PingRsp pingRsp;

        // new variable
        NDISC_Req ndiscReq;
        NDISC_Rsp ndiscRsp;
        LSP_msg lsp;
      } m_message;

  public:
    /**
     *  \returns PingReq Struct
     */
    PingReq GetPingReq ();

    /**
     *  \brief Sets PingReq message params
     *  \param message Payload String
     */

    void SetPingReq (Ipv4Address destinationAddress, std::string message);

    /**
     * \returns PingRsp Struct
     */
    PingRsp GetPingRsp ();
    /**
     *  \brief Sets PingRsp message params
     *  \param message Payload String
     */
    void SetPingRsp (Ipv4Address destinationAddress, std::string message);



    /*----------------------------------------- new methods------------------------------------*/

    NDISC_Req GetNdiscReq ();

    /**
     *  \brief Sets PingReq message params
     *  \param message Payload String
     */

    void SetNdiscReq (std::string message);

    NDISC_Rsp GetNdiscRsp ();

        /**
         *  \brief Sets PingReq message params
         *  \param message Payload String
         */

    void SetNdiscRsp (Ipv4Address destinationAddress, std::string message);

    // LSP

    LSP_msg GetLSP ();

        /**
         *  \brief Sets PingReq message params
         *  \param message Payload String
         */

    void SetLSP (Ipv4Address nodeAddress , std::map<Ipv4Address, NeighborTableEntry> neighborTable);

    void SetTimeStamp(uint32_t timeStamp);

    uint32_t GetTimeStamp();

}; // class LSMessage

static inline std::ostream& operator<< (std::ostream& os, const LSMessage& message)
{
  message.Print (os);
  return os;
}

#endif

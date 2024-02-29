#pragma once

#include <vector>
#include <limits>
#include <cmath>

#include "ns3/address.h"
#include "ns3/callback.h"
#include "ns3/event-id.h"
#include "ns3/net-device.h"
#include "ns3/qbb-net-device.h"
#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/ptr.h"
#include "ns3/settings.h"
#include "ns3/simulator.h"
#include "ns3/tag.h"
#include "ns3/adaptive-voq.h"

namespace ns3{

#define PER_PACKET 0
#define PER_FLOWLET 1

// #if PER_PACKET
// struct adaptiveTxState {
//     uint64_t _seq = 0;
//     uint64_t _activeTime = 0;
// };

// struct adaptiveRxState {
//     uint64_t _activeTime = 0;
//     uint64_t _tailTime = 0;
//     uint64_t _nextSeq = 0;
//     bool _reordering = false;
//     uint64_t _timeExpectedToFlush = 0;
//     uint64_t _timegapAtTx = 0;
//     uint64_t _timeInOrderAtTx = 0;
// };
// #endif

class AdaptiveTag : public Tag {
public:
    AdaptiveTag();
    ~AdaptiveTag();
    static TypeId GetTypeId(void);
    void SetPathId(uint32_t pathId);
    uint32_t GetPathId(void) const;
    void SetHopCount(uint32_t hopCount);
    uint32_t GetHopCount(void) const;
// #if PER_PACKET
//     void SetSeq(uint64_t seq);
//     uint64_t GetSeq(void) const;
//     void SetTimestampTx(uint64_t timestamp);
//     uint64_t GetTimestampTx(void) const;
// #endif
    virtual TypeId GetInstanceTypeId(void) const;
    virtual uint32_t GetSerializedSize(void) const;
    virtual void Serialize(TagBuffer i) const;
    virtual void Deserialize(TagBuffer i);
    virtual void Print(std::ostream& os) const;

private:
    uint32_t m_pathId;
    uint32_t m_hopCount;
// #if PER_PACKET
//     uint64_t m_seq;
//     uint64_t m_timestampTx;
// #endif
};


class AdaptiveRouting: public Object{
    friend class SwitchMmu;
    friend class SwitchNode;

public:
    AdaptiveRouting();

    static TypeId GetTypeId(void);
    static uint64_t GetQpKey(uint32_t dip, uint16_t sport, uint16_t dport, uint16_t pg);
    static uint32_t GetOutPortFromPath(const uint32_t& path, const uint32_t& hopCount);
    static void SetOutPortToPath(uint32_t& path, const uint32_t& hopCount, const uint32_t& outPort);
#if PER_FLOWLET
    static uint32_t nFlowletTimeout;
#endif

    void RouteInput(Ptr<Packet> p, 
                    CustomHeader ch, 
                    double link_utl[128],
                    uint32_t usedEgressPortBytes[128], 
                    uint32_t m_maxBufferBytes);
    uint32_t GetBestPath(uint32_t dstToRId, 
                        double link_utl[128], 
                        uint32_t usedEgressPortBytes[128], 
                        uint32_t m_maxBufferBytes);
    virtual void DoDispose();

    /* SET functions */
    void SetConstants(Time agingTime, Time flowletTimeout);
    void SetSwitchInfo(bool isToR, uint32_t switch_id);

// #if PER_PACKET
//     void DeleteVOQ(uint64_t flowkey);
//     void CallbackByVOQFlush(uint64_t flowkey, uint32_t voqSize);  // used for callback in VOQ
//     void UpdateSeq(uint64_t flowkey, uint64_t seq);
// #endif

    // periodic events for flowlet timeout
    EventId m_agingEvent;
    void AgingEvent();

    /*-----CALLBACK------*/
    void DoSwitchSend(Ptr<Packet> p, CustomHeader& ch, uint32_t outDev, uint32_t qIndex);  // TxToR and Agg/CoreSw
    void DoSwitchSendToDev(Ptr<Packet> p, CustomHeader& ch);  // only at RxToR
    typedef Callback<void, Ptr<Packet>, CustomHeader&, uint32_t, uint32_t> SwitchSendCallback;
    typedef Callback<void, Ptr<Packet>, CustomHeader&> SwitchSendToDevCallback;
    void SetSwitchSendCallback(SwitchSendCallback switchSendCallback);  // set callback
    void SetSwitchSendToDevCallback(SwitchSendToDevCallback switchSendToDevCallback);  // set callback
    /*-----------*/

    // topological info (should be initialized in the beginning)
    std::map<uint32_t, std::set<uint32_t> > m_adaptiveRoutingTable;  // routing table (ToRId -> pathId) (stable)

private:
    // callback
    SwitchSendCallback m_switchSendCallback;  // bound to SwitchNode::SwitchSend (for Request/UDP)
    SwitchSendToDevCallback m_switchSendToDevCallback;  // bound to SwitchNode::SendToDevContinue (for Probe, Reply)

    // topology parameters
    bool m_isToR;          // is ToR (leaf)
    uint32_t m_switch_id;  // switch's nodeID

    Time m_defaultVOQWaitingTime;
    Time m_extraVOQFlushTime;   // extra for uncertainty

    Time m_agingTime;       // expiry of flowlet entry
#if PER_FLOWLET
    Time m_flowletTimeout;  // flowlet timeout (e.g., 100us)

    // local
    std::map<uint64_t, Flowlet*> m_flowletTable;  // QpKey -> Flowlet (at SrcToR)
// #else
//     std::map<uint64_t, adaptiveTxState> m_adaptiveTxTable;
//     std::map<uint64_t, adaptiveRxState> m_adaptiveRxTable;

//     std::unordered_map<uint64_t, AdaptiveVOQ> m_voqMap;
#endif
};

}
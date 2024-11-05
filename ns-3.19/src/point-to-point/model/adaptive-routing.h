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
#define DEBUG 1

class AdaptiveTag : public Tag {
public:
    AdaptiveTag();
    ~AdaptiveTag();
    static TypeId GetTypeId(void);
    void SetPathId(uint32_t pathId);
    uint32_t GetPathId(void) const;
    void SetHopCount(uint32_t hopCount);
    uint32_t GetHopCount(void) const;
    virtual TypeId GetInstanceTypeId(void) const;
    virtual uint32_t GetSerializedSize(void) const;
    virtual void Serialize(TagBuffer i) const;
    virtual void Deserialize(TagBuffer i);
    virtual void Print(std::ostream& os) const;

private:
    uint32_t m_pathId;
    uint32_t m_hopCount;
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

    // void RouteInput(Ptr<Packet> p, 
    //                 CustomHeader ch, 
    //                 double link_utl[128],
    //                 uint32_t usedEgressPortBytes[128], 
    //                 uint32_t m_maxBufferBytes);
    void RouteInput(Ptr<Packet> p, 
                    CustomHeader ch, 
                    const std::vector<Ptr<NetDevice> >& devices, 
                    uint32_t usedEgressPortBytes[128], 
                    uint32_t m_maxBufferBytes);
                    
    // uint32_t GetBestPath(uint32_t dstToRId, 
    //                     double link_utl[128], 
    //                     uint32_t usedEgressPortBytes[128], 
    //                     uint32_t m_maxBufferBytes);
    uint32_t GetBestPath(uint32_t dstToRId, 
                        const std::vector<Ptr<NetDevice> >& devices, 
                        uint32_t usedEgressPortBytes[128], 
                        uint32_t m_maxBufferBytes);
    virtual void DoDispose();

    /* SET functions */
    void SetConstants(Time agingTime, Time flowletTimeout, uint32_t flowletNPackets);
    void SetSwitchInfo(bool isToR, uint32_t switch_id);

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

#if PER_FLOWLET
    Time m_agingTime;       // expiry of flowlet entry
    Time m_flowletTimeout;  // flowlet timeout (e.g., 100us)
    uint32_t m_flowletNPackets;

    // local
    std::map<uint64_t, Flowlet*> m_flowletTable;  // QpKey -> Flowlet (at SrcToR)
#endif
};

}
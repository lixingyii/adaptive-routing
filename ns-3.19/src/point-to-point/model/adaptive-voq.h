#ifndef __ADAPTIVE_VOQ_H__
#define __ADAPTIVE_VOQ_H__

#include <map>
#include <queue>
#include <unordered_map>
#include <vector>

#include "ns3/address.h"
#include "ns3/callback.h"
#include "ns3/custom-header.h"
#include "ns3/event-id.h"
#include "ns3/log.h"
#include "ns3/net-device.h"
#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/ptr.h"
#include "ns3/settings.h"
#include "ns3/simulator.h"

namespace ns3 {

class AdaptiveVOQ {
    friend class AdaptiveRouting;

public:
    AdaptiveVOQ();
    ~AdaptiveVOQ();

    void Set(uint64_t flowkey, uint32_t dip, Time timeToFlush, Time extraVOQFlushTime, uint64_t seq);
    void Enqueue(uint64_t seq, Ptr<Packet> pkt);
    void FlushAllImmediately();
    void EnforceFlushAll();
    void RescheduleFlush(Time timeToFlush);
    void RescheduleFlushImmediately();
    bool CheckEmpty();
    uint32_t getQueueSize();
    uint32_t getDIP() { return m_dip; };

    static std::vector<int> m_flushEstErrorhistory;

private:
    uint64_t m_flowkey;               // flowkey (voqMap's key)
    uint32_t m_dip;                   // destination ip (for monitoring)
    std::map<uint64_t, Ptr<Packet> > m_buffer;
    EventId m_checkFlushEvent;  // check flush schedule is on-going (will be false once the queue
                                // starts flushing)
    Time m_extraVOQFlushTime; // extra flush time (for network uncertainty) -- for debugging
    uint64_t m_seq;

    // callback
    Callback<void, uint64_t> m_deleteCallback;  // bound to SlbRouting::DeleteVoQ
    Callback<void, uint64_t, uint32_t> m_CallbackByVOQFlush;  // bound to SlbRouting::CallbackByVOQFlush
    Callback<void, uint64_t, uint64_t> m_updateSeqCallback;
    Callback<void, Ptr<Packet>, CustomHeader&> m_switchSendToDevCallback;  // bound to SlbRouting::DoSwitchSendToDev

};

}  // namespace ns3

#endif
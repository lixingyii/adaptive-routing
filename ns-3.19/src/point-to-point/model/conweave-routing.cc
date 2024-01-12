/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2023 NUS
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
 *
 * Authors: Chahwan Song <songch@comp.nus.edu.sg>
 */

#include "ns3/conweave-routing.h"

#include <assert.h>
#include <stdio.h>

#include <algorithm>
#include <random>

#include "ns3/assert.h"
#include "ns3/event-id.h"
#include "ns3/flow-id-tag.h"
#include "ns3/ipv4-header.h"
#include "ns3/log.h"
#include "ns3/nstime.h"
#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/ppp-header.h"
#include "ns3/qbb-header.h"
#include "ns3/random-variable.h"
#include "ns3/settings.h"
#include "ns3/simulator.h"
#include "ns3/udp-header.h"

namespace ns3 {

/**
 * @brief tag for DATA header
 */
ConWeaveDataTag::ConWeaveDataTag() : Tag() {}
TypeId ConWeaveDataTag::GetTypeId(void) {
    static TypeId tid =
        TypeId("ns3::ConWeaveDataTag").SetParent<Tag>().AddConstructor<ConWeaveDataTag>();
    return tid;
}
void ConWeaveDataTag::SetPathId(uint32_t pathId) { m_pathId = pathId; }
uint32_t ConWeaveDataTag::GetPathId(void) const { return m_pathId; }
void ConWeaveDataTag::SetHopCount(uint32_t hopCount) { m_hopCount = hopCount; }
uint32_t ConWeaveDataTag::GetHopCount(void) const { return m_hopCount; }
void ConWeaveDataTag::SetEpoch(uint32_t epoch) { m_epoch = epoch; }
uint32_t ConWeaveDataTag::GetEpoch(void) const { return m_epoch; }
void ConWeaveDataTag::SetPhase(uint32_t phase) { m_phase = phase; }
uint32_t ConWeaveDataTag::GetPhase(void) const { return m_phase; }
void ConWeaveDataTag::SetTimestampTx(uint64_t timestamp) { m_timestampTx = timestamp; }
uint64_t ConWeaveDataTag::GetTimestampTx(void) const { return m_timestampTx; }
void ConWeaveDataTag::SetTimestampTail(uint64_t timestamp) { m_timestampTail = timestamp; }
uint64_t ConWeaveDataTag::GetTimestampTail(void) const { return m_timestampTail; }
void ConWeaveDataTag::SetFlagData(uint32_t flag) { m_flagData = flag; }
uint32_t ConWeaveDataTag::GetFlagData(void) const { return m_flagData; }

TypeId ConWeaveDataTag::GetInstanceTypeId(void) const { return GetTypeId(); }
uint32_t ConWeaveDataTag::GetSerializedSize(void) const {
    return sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) +
           sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint32_t);
}
void ConWeaveDataTag::Serialize(TagBuffer i) const {
    i.WriteU32(m_pathId);
    i.WriteU32(m_hopCount);
    i.WriteU32(m_epoch);
    i.WriteU32(m_phase);
    i.WriteU64(m_timestampTx);
    i.WriteU64(m_timestampTail);
    i.WriteU32(m_flagData);
}
void ConWeaveDataTag::Deserialize(TagBuffer i) {
    m_pathId = i.ReadU32();
    m_hopCount = i.ReadU32();
    m_epoch = i.ReadU32();
    m_phase = i.ReadU32();
    m_timestampTx = i.ReadU64();
    m_timestampTail = i.ReadU64();
    m_flagData = i.ReadU32();
}
void ConWeaveDataTag::Print(std::ostream &os) const {
    os << "m_pathId=" << m_pathId;
    os << ", m_hopCount=" << m_hopCount;
    os << ", m_epoch=" << m_epoch;
    os << ", m_phase=" << m_phase;
    os << ". m_timestampTx=" << m_timestampTx;
    os << ", m_timestampTail=" << m_timestampTail;
    os << ", m_flagData=" << m_flagData;
}

/**
 * @brief tag for reply/notify packet
 */
ConWeaveReplyTag::ConWeaveReplyTag() : Tag() {}
TypeId ConWeaveReplyTag::GetTypeId(void) {
    static TypeId tid =
        TypeId("ns3::ConWeaveReplyTag").SetParent<Tag>().AddConstructor<ConWeaveReplyTag>();
    return tid;
}
void ConWeaveReplyTag::SetFlagReply(uint32_t flagReply) { m_flagReply = flagReply; }
uint32_t ConWeaveReplyTag::GetFlagReply(void) const { return m_flagReply; }
void ConWeaveReplyTag::SetEpoch(uint32_t epoch) { m_epoch = epoch; }
uint32_t ConWeaveReplyTag::GetEpoch(void) const { return m_epoch; }
void ConWeaveReplyTag::SetPhase(uint32_t phase) { m_phase = phase; }
uint32_t ConWeaveReplyTag::GetPhase(void) const { return m_phase; }
TypeId ConWeaveReplyTag::GetInstanceTypeId(void) const { return GetTypeId(); }
uint32_t ConWeaveReplyTag::GetSerializedSize(void) const {
    return sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t);
}
void ConWeaveReplyTag::Serialize(TagBuffer i) const {
    i.WriteU32(m_flagReply);
    i.WriteU32(m_epoch);
    i.WriteU32(m_phase);
}
void ConWeaveReplyTag::Deserialize(TagBuffer i) {
    m_flagReply = i.ReadU32();
    m_epoch = i.ReadU32();
    m_phase = i.ReadU32();
}
void ConWeaveReplyTag::Print(std::ostream &os) const {
    os << "m_flagReply=" << m_flagReply;
    os << "m_epoch=" << m_epoch;
    os << "m_phase=" << m_phase;
}

/**
 * @brief tag for notify packet
 */
ConWeaveNotifyTag::ConWeaveNotifyTag() : Tag() {}
TypeId ConWeaveNotifyTag::GetTypeId(void) {
    static TypeId tid =
        TypeId("ns3::ConWeaveNotifyTag").SetParent<Tag>().AddConstructor<ConWeaveNotifyTag>();
    return tid;
}
void ConWeaveNotifyTag::SetPathId(uint32_t pathId) { m_pathId = pathId; }
uint32_t ConWeaveNotifyTag::GetPathId(void) const { return m_pathId; }
TypeId ConWeaveNotifyTag::GetInstanceTypeId(void) const { return GetTypeId(); }
uint32_t ConWeaveNotifyTag::GetSerializedSize(void) const { return sizeof(uint32_t); }
void ConWeaveNotifyTag::Serialize(TagBuffer i) const { i.WriteU32(m_pathId); }
void ConWeaveNotifyTag::Deserialize(TagBuffer i) { m_pathId = i.ReadU32(); }
void ConWeaveNotifyTag::Print(std::ostream &os) const { os << "m_pathId=" << m_pathId; }

/*---------------- ConWeaveRouting ---------------*/
// debugging to check timing
uint64_t ConWeaveRouting::debug_time = 0;

// static members for topology information and statistics
uint64_t ConWeaveRouting::m_nReplyInitSent = 0;
uint64_t ConWeaveRouting::m_nReplyTailSent = 0;
uint64_t ConWeaveRouting::m_nTimelyInitReplied = 0;
uint64_t ConWeaveRouting::m_nTimelyTailReplied = 0;
uint64_t ConWeaveRouting::m_nNotifySent = 0;
uint64_t ConWeaveRouting::m_nReRoute = 0;
uint64_t ConWeaveRouting::m_nOutOfOrderPkts = 0;
uint64_t ConWeaveRouting::m_nFlushVOQTotal = 0;
uint64_t ConWeaveRouting::m_nFlushVOQByTail = 0;
std::vector<uint32_t> ConWeaveRouting::m_historyVOQSize;

// functions
ConWeaveRouting::ConWeaveRouting() {
    m_isToR = false;
    m_switch_id = (uint32_t)-1;

    // set constants
    m_extraReplyDeadline = MicroSeconds(4);       // 1 hop of 50KB / 100Gbps = 4us
    m_extraVOQFlushTime = MicroSeconds(8);        // for uncertainty
    m_txExpiryTime = MicroSeconds(300);           // flowlet timegap
    m_defaultVOQWaitingTime = MicroSeconds(200);  // 200us
    m_pathPauseTime = MicroSeconds(8);            // 100KB queue, 100Gbps -> 8us
    m_pathAwareRerouting = true;                  // enable path-aware rerouting
    m_agingTime = MilliSeconds(2);                // 2ms
    m_conweavePathTable.resize(65536);            // initialize table size
}

ConWeaveRouting::~ConWeaveRouting() {}
void ConWeaveRouting::DoDispose() { m_agingEvent.Cancel(); }
TypeId ConWeaveRouting::GetTypeId(void) {
    static TypeId tid =
        TypeId("ns3::ConWeaveRouting").SetParent<Object>().AddConstructor<ConWeaveRouting>();
    return tid;
}

uint32_t ConWeaveRouting::GetOutPortFromPath(const uint32_t &path, const uint32_t &hopCount) {
    return ((uint8_t *)&path)[hopCount];
}

void ConWeaveRouting::SetOutPortToPath(uint32_t &path, const uint32_t &hopCount,
                                       const uint32_t &outPort) {
    ((uint8_t *)&path)[hopCount] = outPort;
}

// 使用给定的 IP 地址和端口号构建一个唯一的flowkey
uint64_t ConWeaveRouting::GetFlowKey(uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2) {
    /** IP_ADDRESS: 11.X.X.1 */
    // 检查ip格式是否为11.X.X.1
    assert(((ip1 & 0xff000000) >> 24) == 11);
    assert(((ip2 & 0xff000000) >> 24) == 11);
    assert((ip1 & 0x000000ff) == 1);
    assert((ip2 & 0x000000ff) == 1);

    uint64_t ret = 0;
    ret += uint64_t((ip1 & 0x00ffff00) >> 8) + uint64_t((uint32_t)port1 << 16);
    ret = ret << 32;
    ret += uint64_t((ip2 & 0x00ffff00) >> 8) + uint64_t((uint32_t)port2 << 16);
    return ret;
}

uint32_t ConWeaveRouting::DoHash(const uint8_t *key, size_t len, uint32_t seed) {
    uint32_t h = seed;
    if (len > 3) {
        const uint32_t *key_x4 = (const uint32_t *)key;
        size_t i = len >> 2;
        do {
            uint32_t k = *key_x4++;
            k *= 0xcc9e2d51;
            k = (k << 15) | (k >> 17);
            k *= 0x1b873593;
            h ^= k;
            h = (h << 13) | (h >> 19);
            h += (h << 2) + 0xe6546b64;
        } while (--i);
        key = (const uint8_t *)key_x4;
    }
    if (len & 3) {
        size_t i = len & 3;
        uint32_t k = 0;
        key = &key[i - 1];
        do {
            k <<= 8;
            k |= *key--;
        } while (--i);
        k *= 0xcc9e2d51;
        k = (k << 15) | (k >> 17);
        k *= 0x1b873593;
        h ^= k;
    }
    h ^= len;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

void ConWeaveRouting::SendReply(Ptr<Packet> p, CustomHeader &ch, uint32_t flagReply,
                                uint32_t pkt_epoch) {
    
    // 构造Reply Packet：
    // 创建 qbbHeader 对象，设置其字段，表示序列号、PG、源端口、目的端口等信息。
    // 创建 Ipv4Header 对象，设置源地址、目的地址、协议类型等信息。
    // 创建 PppHeader 对象，设置协议类型，将 qbbHeader 和 Ipv4Header 添加到 Reply Packet 中。
    qbbHeader seqh;
    seqh.SetSeq(0);
    seqh.SetPG(ch.udp.pg);
    seqh.SetSport(ch.udp.dport);
    seqh.SetDport(ch.udp.sport);
    seqh.SetIntHeader(ch.udp.ih);

    Ptr<Packet> replyP = Create<Packet>(
        std::max(64 - 14 - 20 - (int)seqh.GetSerializedSize(), 0));  // at least 64 Bytes
    replyP->AddHeader(seqh);                                         // qbbHeader

    // ACK-like packet, no L4 header
    Ipv4Header ipv4h;
    ipv4h.SetSource(Ipv4Address(ch.dip));
    ipv4h.SetDestination(Ipv4Address(ch.sip));
    ipv4h.SetProtocol(0xFD);  // (N)ACK - (IRN)
    ipv4h.SetTtl(64);
    ipv4h.SetPayloadSize(replyP->GetSize());
    ipv4h.SetIdentification(UniformVariable(0, 65536).GetValue());
    replyP->AddHeader(ipv4h);  // ipv4Header

    PppHeader ppp;
    ppp.SetProtocol(0x0021);  // EtherToPpp(0x800), see point-to-point-net-device.cc
    replyP->AddHeader(ppp);   // pppHeader

    // attach slbControlTag
    // 添加ConWeaveReplyTag：
    // 创建 ConWeaveReplyTag 对象，设置其字段，表示回复的类型（INIT或TAIL）、回复所在的Epoch，以及阶段（Phase）。
    // 将 ConWeaveReplyTag 添加到 Reply Packet 的标签中。
    ConWeaveReplyTag conweaveReplyTag;
    conweaveReplyTag.SetFlagReply(flagReply);
    conweaveReplyTag.SetEpoch(pkt_epoch);
    if (flagReply == ConWeaveReplyTag::INIT) {
        ConWeaveRouting::m_nReplyInitSent += 1;
        conweaveReplyTag.SetPhase(0);
    } else if (flagReply == ConWeaveReplyTag::TAIL) {
        ConWeaveRouting::m_nReplyTailSent += 1;
        conweaveReplyTag.SetPhase(1);
    } else {
        SLB_LOG("ERROR - Unknown ConWeaveReplyTag flag:" << flagReply);
        exit(1);
    }

    replyP->AddPacketTag(conweaveReplyTag);

    // 设置Dummy InDev接口：
    // 添加一个 FlowIdTag，其值为 Settings::CONWEAVE_CTRL_DUMMY_INDEV，表示Dummy InDev接口。
    // dummy reply's inDev interface
    replyP->AddPacketTag(FlowIdTag(Settings::CONWEAVE_CTRL_DUMMY_INDEV));

    // extract customheader
    CustomHeader replyCh(CustomHeader::L2_Header | CustomHeader::L3_Header |
                         CustomHeader::L4_Header);
    replyP->PeekHeader(replyCh);

    // send reply packets
    SLB_LOG(PARSE_FIVE_TUPLE(ch) << "================================### Send REPLY"
                                 << ",ReplyFlag:" << flagReply);
    DoSwitchSendToDev(replyP, replyCh);  // will have ACK's priority
    return;
}

void ConWeaveRouting::SendNotify(Ptr<Packet> p, CustomHeader &ch, uint32_t pathId) {
    qbbHeader seqh;
    seqh.SetSeq(0);
    seqh.SetPG(ch.udp.pg);
    seqh.SetSport(ch.udp.dport);
    seqh.SetDport(ch.udp.sport);
    seqh.SetIntHeader(ch.udp.ih);

    Ptr<Packet> fbP = Create<Packet>(
        std::max(64 - 14 - 20 - (int)seqh.GetSerializedSize(), 0));  // at least 64 Bytes
    fbP->AddHeader(seqh);                                            // qbbHeader

    // ACK-like packet, no L4 header
    Ipv4Header ipv4h;
    ipv4h.SetSource(Ipv4Address(ch.dip));
    ipv4h.SetDestination(Ipv4Address(ch.sip));
    ipv4h.SetProtocol(0xFD);  // (N)ACK - (IRN)
    ipv4h.SetTtl(64);
    ipv4h.SetPayloadSize(fbP->GetSize());
    ipv4h.SetIdentification(UniformVariable(0, 65536).GetValue());
    fbP->AddHeader(ipv4h);  // ipv4Header

    PppHeader ppp;
    ppp.SetProtocol(0x0021);  // EtherToPpp(0x800), see point-to-point-net-device.cc
    fbP->AddHeader(ppp);      // pppHeader

    // attach ConWeaveNotifyTag
    ConWeaveNotifyTag conweaveNotifyTag;
    conweaveNotifyTag.SetPathId(pathId);
    fbP->AddPacketTag(conweaveNotifyTag);

    // dummy notify's inDev interface
    fbP->AddPacketTag(FlowIdTag(Settings::CONWEAVE_CTRL_DUMMY_INDEV));

    // extract customheader
    CustomHeader fbCh(CustomHeader::L2_Header | CustomHeader::L3_Header | CustomHeader::L4_Header);
    fbP->PeekHeader(fbCh);

    /** OVERHEAD: reply overhead statistics **/
    ConWeaveRouting::m_nNotifySent += 1;

    // send notify packets
    SLB_LOG(PARSE_FIVE_TUPLE(ch) << "================================### Send NOTIFY");
    DoSwitchSendToDev(fbP, fbCh);  // will have ACK's priority
    return;
}

/** MAIN: Every SLB packet is hijacked to this function at switches */
void ConWeaveRouting::RouteInput(Ptr<Packet> p, CustomHeader &ch) {
    // Packet arrival time
    Time now = Simulator::Now();

    // Turn on aging event scheduler if it is not running
    if (!m_agingEvent.IsRunning()) {
        SLB_LOG("ConWeave routing restarts aging event scheduling:" << m_switch_id << now);
        m_agingEvent = Simulator::Schedule(m_agingTime, &ConWeaveRouting::AgingEvent, this);
    }

    // get srcToRId, dstToRId
    assert(Settings::hostIp2SwitchId.find(ch.sip) !=
           Settings::hostIp2SwitchId.end());  // Misconfig of Settings::hostIp2SwitchId - sip
    assert(Settings::hostIp2SwitchId.find(ch.dip) !=
           Settings::hostIp2SwitchId.end());  // Misconfig of Settings::hostIp2SwitchId - dip
    uint32_t srcToRId = Settings::hostIp2SwitchId[ch.sip];
    uint32_t dstToRId = Settings::hostIp2SwitchId[ch.dip];

    /** FILTER: Quickly filter intra-pod traffic */
    if (srcToRId == dstToRId) {  // do normal routing (only one path)
        DoSwitchSendToDev(p, ch);
        return;
    }
    assert(srcToRId != dstToRId);  // Should not be in the same pod

    if (ch.l3Prot != 0x11 && ch.l3Prot != 0xFD) {
        SLB_LOG(PARSE_FIVE_TUPLE(ch) << "ACK/PFC or other control pkts -> do flow-ECMP. Sw("
                                     << m_switch_id << "),l3Prot:" << ch.l3Prot);
        DoSwitchSendToDev(p, ch);
        return;
    }
    assert(ch.l3Prot == 0x11 || ch.l3Prot == 0xFD);  // Only supports UDP (data) or (N)ACK packets

    // get conweaveDataTag from packet
    ConWeaveDataTag conweaveDataTag;
    bool foundConWeaveDataTag = p->PeekPacketTag(conweaveDataTag);

    // get SlbControlTag from packet
    ConWeaveReplyTag conweaveReplyTag;
    bool foundConWeaveReplyTag = p->PeekPacketTag(conweaveReplyTag);

    // get conweaveNotifyTag from packet
    ConWeaveNotifyTag conweaveNotifyTag;
    bool foundConWeaveNotifyTag = p->PeekPacketTag(conweaveNotifyTag);

    if (ch.l3Prot == 0xFD) { /** ACK or ConWeave's Control Packets */
        /** NOTE: ConWeave uses 0xFD protocol id for its control packets.
         * Quick filter purely (N)ACK packets (not ConWeave control packets)
         **/
        if (!foundConWeaveReplyTag && !foundConWeaveNotifyTag) {  // pure-(N)ACK
            if (m_switch_id == srcToRId) {
                SLB_LOG(PARSE_FIVE_TUPLE(ch)
                        << "[TxToR/*PureACK] Sw(" << m_switch_id << "),ACK detected");
            }
            if (m_switch_id == dstToRId) {
                SLB_LOG(PARSE_FIVE_TUPLE(ch)
                        << "[RxToR/*PureACK] Sw(" << m_switch_id << "),ACK detected");
            }
            DoSwitchSendToDev(p, ch);
            return;
        }

        /** NOTE: ConWeave's control packets are forwarded with default flow-ECMP */
        if (!m_isToR) {
            SLB_LOG(PARSE_FIVE_TUPLE(ch) << "ConWeave Ctrl Pkts use flow-ECMP at non-ToR switches");
            DoSwitchSendToDev(p, ch);
            return;
        }
    }

    // print every 1ms for logging
    if (Simulator::Now().GetMilliSeconds() > debug_time) {
        std::cout << "[Logging] Current time: " << Simulator::Now() << std::endl;
        debug_time = Simulator::Now().GetMilliSeconds();
    }

    /**------------------------  Start processing SLB packets  ------------------------*/
    if (m_isToR) {  // ToR switch
        /***************************
         *    Source ToR Switch    *
         ***************************/
        if (m_switch_id == srcToRId) {  // SrcToR -
            assert(ch.l3Prot == 0x11);  // Only UDP (Data) - TxToR can see only UDP (DATA) packets
            assert(!foundConWeaveDataTag &&
                   !foundConWeaveReplyTag);  // ERROR - dataTag and replyTag
                                             // should not be found at TxToR

            /** PIPELINE: emulating the p4 pipelining */
            conweaveTxMeta tx_md;  // SrcToR packet metadata
            tx_md.pkt_flowkey = GetFlowKey(ch.sip, ch.dip, ch.udp.sport, ch.udp.dport);
            auto &txEntry = m_conweaveTxTable[tx_md.pkt_flowkey];

            /** INIT: initialize flowkey */
            // 获取或创建conweaveTxTable中的条目 (txEntry):
            // 通过m_conweaveTxTable（源ToR交换机的状态表）获取或创建一个与流相关的条目。
            // 如果是新连接，将newConnection标志设置为true，并将相关信息初始化。
            if (txEntry._flowkey == 0) { /* if new */
                txEntry._flowkey = tx_md.pkt_flowkey;
                tx_md.newConnection = true;
            }
            uint64_t baseRTT =
                m_rxToRId2BaseRTT[dstToRId];  // get base RTT (used for setting REPLY timer)

            /**
             * CHECK: Expiry or Stability
             */
            // 检查txEntry的激活时间（_activeTime）和过期时间（m_txExpiryTime）来确定是否过期。
            // 如果过期，将flagExpired标志设置为true，并将稳定状态 (_stabilized) 设置为false。
            // 如果未过期但已稳定，将flagStabilized标志设置为true。
            if (txEntry._activeTime + m_txExpiryTime < now) { /* expired */
                tx_md.flagExpired = true;
                txEntry._stabilized = false;
            } else if (txEntry._stabilized == true) { /* stabilized */
                tx_md.flagStabilized = true;
                txEntry._stabilized = false;
            }
            // 更新txEntry的激活时间为当前时间。
            txEntry._activeTime = now;  // record the entry's last-accessed time

            // sanity check - new connections are first always having "expired" flag
            if (tx_md.newConnection) {
                assert(tx_md.flagExpired == true);
            }

            /** ACTIVE: if expired or stabilized, reset timer. Otherwise, check timeout */
            // 如果连接过期或已稳定，重新设置REPLY计时器（_replyTimer），并设置新的REPLY截止时间。
            // 如果REPLY计时器已超时，将flagReplyTimeout标志设置为true，表示需要创建TAIL数据包。
            if (tx_md.flagExpired ||
                tx_md.flagStabilized) { /* expired or stabilized -> send INIT  */
                txEntry._replyTimer =
                    now + NanoSeconds(baseRTT) + m_extraReplyDeadline; /* set new reply deadline */
            } else if (txEntry._replyTimer < now) { /* reply-timeout -> send TAIL */
                txEntry._replyTimer = CW_MAX_TIME;
                tx_md.flagReplyTimeout = true; /* create TAIL packet */
            }

            SLB_LOG(PARSE_FIVE_TUPLE(ch)
                    << "\t[TxToR/UDP] Sw(" << m_switch_id << "),E/R/S:" << tx_md.flagExpired << "/"
                    << tx_md.flagReplyTimeout << "/" << tx_md.flagStabilized
                    << ",flowkey:" << tx_md.pkt_flowkey);
            if (tx_md.newConnection) {
                SLB_LOG(PARSE_FIVE_TUPLE(ch)
                        << "\t--> new connection with flowkey:" << tx_md.pkt_flowkey);
            }

            /**
             * ROUND: if expiry or stabilized, increase epoch by 1
             */
            // 处理轮次和阶段 (epoch和phase):
            // 根据连接的状态，更新连接的epoch和phase。
            // 如果连接过期或已稳定，epoch加1。根据连接的状态，确定数据包的phase。
            if (tx_md.flagExpired || tx_md.flagStabilized) { /* expired or stabilized */
                txEntry._epoch += 1;
                tx_md.epoch = txEntry._epoch; /* increase and get */
            } else {                          /* reply-timeout, or usual */
                tx_md.epoch = txEntry._epoch; /* just get */
            }

            /**
             * PHASE: expiry, stabilized, reply-timeout, or just get
             */
            if (tx_md.flagExpired || tx_md.flagStabilized) { /* expired or stabilized  */
                txEntry._phase = 0;                          /* set phase to 0 */
                tx_md.phase = 0;                             /* pkt's phase = 0 */
            } else if (tx_md.flagReplyTimeout) {
                assert(txEntry._phase == 0);
                txEntry._phase = 1; /* set phase to 1 */
                tx_md.phase = 0;    /* pkt's phase = 0 */
            } else {                /* normal pkt */
                tx_md.phase = txEntry._phase;
            }

            /**
             * PATH: sample 2 ports and choose a good port
             */
            // 获取可选的路径 (pathSet):
            // 从m_ConWeaveRoutingTable中获取目标ToR交换机 (dstToRId) 的路径集合 (pathSet)。
            std::set<uint32_t> pathSet = m_ConWeaveRoutingTable[dstToRId];  // pathSet to RxToR
            // 初始化路径 (initPath):
            // 随机选择路径集合中的一个路径作为初始路径 (initPath)。这个路径在初始状态下是空的，用CW_DEFAULT_32BIT表示。
            uint32_t initPath =
                *(std::next(pathSet.begin(),
                            rand() % pathSet.size()));  // to initialize (empty: CW_DEFAULT_32BIT)

            // 路径感知 
            if (m_pathAwareRerouting) {
                /* path-aware decision */
                // 随机选择两个路径 (randPath1和randPath2)
                uint32_t randPath1 = *(std::next(pathSet.begin(), rand() % pathSet.size()));
                uint32_t randPath2 = *(std::next(pathSet.begin(), rand() % pathSet.size()));
                // 获取这两个路径在m_conweavePathTable中的信息 (pathEntry1和pathEntry2)
                const auto pathEntry1 =
                    m_conweavePathTable[DoHash((uint8_t *)&randPath1, 4, m_switch_id) %
                                        m_conweavePathTable.size()];
                const auto pathEntry2 =
                    m_conweavePathTable[DoHash((uint8_t *)&randPath2, 4, m_switch_id) %
                                        m_conweavePathTable.size()];
                bool goodPath1 = true;
                bool goodPath2 = true;

                // 检查这两个路径是否被标记为ECN（Explicit Congestion Notification）。
                // 如果被标记，将对应的goodPath1或goodPath2设置为false，表示不是好的路径。
                if (pathEntry1._pathId == randPath1 &&
                    pathEntry1._invalidTime > now) {  // ECN marked
                    goodPath1 = false;
                }
                if (pathEntry2._pathId == randPath2 &&
                    pathEntry2._invalidTime > now) {  // ECN marked
                    goodPath2 = false;
                }

                // 如果goodPath1为true，将tx_md.foundGoodPath设置为true，并将tx_md.goodPath设置为randPath1。
                // 如果goodPath2为true，同样设置相关标志。
                if (goodPath1 == true) {
                    tx_md.foundGoodPath = true;
                    tx_md.goodPath = randPath1;
                    // SLB_LOG(PARSE_FIVE_TUPLE(ch) << "--> First trial has good path");
                } else if (goodPath2 == true) {
                    tx_md.foundGoodPath = true;
                    tx_md.goodPath = randPath2;
                    // SLB_LOG(PARSE_FIVE_TUPLE(ch) << "--> Second trial has good path");
                } else {  // 如果无法找到好的路径，设置tx_md.goodPath为randPath1，表示选择一个随机路径（未使用）。
                    assert(tx_md.foundGoodPath == false);
                    tx_md.goodPath = randPath1;  // random path (unused)
                    // SLB_LOG(PARSE_FIVE_TUPLE(ch) << "--> Cannot find good path, so use current
                    // path");
                }
            } else {
                // 如果未启用路径感知重路由，直接随机选择一个路径作为好的路径。将tx_md.foundGoodPath设置为true，tx_md.goodPath设置为所选的随机路径。
                /* random path selection */
                tx_md.foundGoodPath = true;
                tx_md.goodPath = *(std::next(pathSet.begin(), rand() % pathSet.size()));
            }

            /** PATH: update and get current path */
            /** NOTE: if new connection, set initial random path */
            // 如果是新连接，且当前路径 (txEntry._pathId) 为初始值 CW_DEFAULT_32BIT，则将其设置为好的路径 (tx_md.goodPath)
            if (txEntry._pathId == CW_DEFAULT_32BIT) {
                assert(tx_md.newConnection == true);
                txEntry._pathId = tx_md.goodPath;
            }
            // 如果连接已经过期 (tx_md.flagExpired)，并且找到了好的路径 (tx_md.foundGoodPath)，则更新路径。
            // 记录重新路由次数 (ConWeaveRouting::m_nReRoute)，并将当前路径 (tx_md.currPath) 设置为新的路径 (txEntry._pathId)。
            if (tx_md.flagExpired) { /* expired -> update path and use the new path */
                if (tx_md.foundGoodPath) {
                    ConWeaveRouting::m_nReRoute += (tx_md.newConnection == false ? 1 : 0);
                    txEntry._pathId = tx_md.goodPath;
                    SLB_LOG(PARSE_FIVE_TUPLE(ch)
                            << "\t#*#*#*#*#*#*#*#*#*#*#*#* EXPIRED -> PATH CHANGED to "
                            << txEntry._pathId << " #*#*#*#*#*#*#*#*#*#*#*#*");
                }
                tx_md.currPath = txEntry._pathId;
            } else if (tx_md.flagReplyTimeout) {  /* reply-timeout -> update path but use the
                                                     previous path (TAIL pkt) */
                // 如果是回复超时 (tx_md.flagReplyTimeout)，也更新路径。
                // 在这种情况下，当前路径 (tx_md.currPath) 仍然使用之前的路径 (txEntry._pathId)，但将路径更新为好的路径 (txEntry._pathId)。
                // 同样，记录重新路由次数。
                tx_md.currPath = txEntry._pathId; /* TAIL uses current path. */
                if (tx_md.foundGoodPath) {        /* next pkts will use the (changed) next path */
                    ConWeaveRouting::m_nReRoute += (tx_md.newConnection == false ? 1 : 0);
                    txEntry._pathId = tx_md.goodPath;
                    SLB_LOG(PARSE_FIVE_TUPLE(ch)
                            << "\t#*#*#*#*#*#*#*#*#*#*#*#* REPLY TIMEOUT -> PATH CHANGED to "
                            << txEntry._pathId << " #*#*#*#*#*#*#*#*#*#*#*#*");
                }
            } else { /* stabilized or usual -> use current path and do not change the path */
                // 如果是稳定状态或普通情况，保持当前路径 (tx_md.currPath) 与连接表中的路径 (txEntry._pathId) 一致。
                tx_md.currPath = txEntry._pathId;
            }

            /** TAILTIME: Memorize TAIL packet timestamp or get if phase=1 */
            if (tx_md.flagExpired) { /* expiry -> set zero */
                // 如果连接已过期 (tx_md.flagExpired)，将TAIL时间 (tx_md.tailTime) 设置为零
                txEntry._tailTime = NanoSeconds(0);
            } else if (tx_md.flagReplyTimeout) { /* reply-timeout -> set now */
                // 如果是回复超时 (tx_md.flagReplyTimeout)，将TAIL时间 (tx_md.tailTime) 设置为当前时间 (now)。
                txEntry._tailTime = now;
            } else if (tx_md.flagStabilized) { /* stabilized -> set zero */
                // 如果是稳定状态 (tx_md.flagStabilized)，将TAIL时间 (tx_md.tailTime) 设置为零。
                txEntry._tailTime = NanoSeconds(0);
            }
            tx_md.tailTime = txEntry._tailTime.GetNanoSeconds();

            /**
             * SUMMARY: based on tx_md, update packet header
             */
            // 更新数据包头部信息:
            // 根据 tx_md 中的信息，更新 conweaveDataTag 标签的路径 (SetPathId)、跳数 (SetHopCount)、时期 (SetEpoch)、阶段 (SetPhase)、发送时间戳 (SetTimestampTx) 和 TAIL 时间戳 (SetTimestampTail)。
            // 根据连接的状态（过期、回复超时、稳定）设置数据包标志 (SetFlagData)，可以是 INIT、TAIL 或 DATA。
            conweaveDataTag.SetPathId(tx_md.currPath);
            conweaveDataTag.SetHopCount(0);
            conweaveDataTag.SetEpoch(tx_md.epoch);
            conweaveDataTag.SetPhase(tx_md.phase);
            conweaveDataTag.SetTimestampTx(now.GetNanoSeconds());
            conweaveDataTag.SetTimestampTail(tx_md.tailTime);
            if (tx_md.flagExpired || tx_md.flagStabilized) { /* ask reply of INIT */
                conweaveDataTag.SetFlagData(ConWeaveDataTag::INIT);
                assert(tx_md.phase == 0);
            } else if (tx_md.flagReplyTimeout) { /* ask reply of TAIL (CLEAR packet) */
                conweaveDataTag.SetFlagData(ConWeaveDataTag::TAIL);
                assert(tx_md.phase == 0);
            } else {
                conweaveDataTag.SetFlagData(ConWeaveDataTag::DATA);
            }
            p->AddPacketTag(conweaveDataTag);

            uint32_t outDev =
                GetOutPortFromPath(conweaveDataTag.GetPathId(), conweaveDataTag.GetHopCount());
            uint32_t qIndex = ch.udp.pg;
            SLB_LOG(PARSE_FIVE_TUPLE(ch)
                    << "\t--> outDev:" << outDev << ",qIndex:" << qIndex
                    << ",pktEpoch:" << tx_md.epoch << ",pktPhase:" << tx_md.phase
                    << ",tailTime:" << tx_md.tailTime << ",pktPath:" << conweaveDataTag.GetPathId()
                    << ",flag:" << conweaveDataTag.GetFlagData() << " (2:INIT,3:TAIL)");
            DoSwitchSend(p, ch, outDev, qIndex);
            return;
        }
        /***************************
         *  Destination ToR Switch *
         ***************************/
        else if (m_switch_id == dstToRId) {
            if (foundConWeaveDataTag) {  // DATA

                /** PIPELINE: emulating the p4 pipelining */
                // 初始化 Rx 元数据 (rx_md)：
                // 使用数据包的源、目的 IP 和端口信息获取数据包的流键 (pkt_flowkey)。
                // 通过流键获取或创建 Rx 表项 (rxEntry)。
                // 如果 Rx 表项的流键为零，则将其设置为当前数据包的流键，并将时期 (epoch) 设置为 1，表示新连接。
                conweaveRxMeta rx_md;
                rx_md.pkt_flowkey = GetFlowKey(ch.sip, ch.dip, ch.udp.sport, ch.udp.dport);
                auto &rxEntry = m_conweaveRxTable[rx_md.pkt_flowkey];

                /** INIT: setup flowkey */
                if (rxEntry._flowkey == 0) {
                    rxEntry._flowkey = rx_md.pkt_flowkey;
                    assert(rxEntry._epoch == 1);  // sanity check
                    rx_md.newConnection = true;
                }

                /**
                 * ACTIVE: update active time (for aging)
                 */
                // 更新活动时间 (_activeTime)：
                // 更新 Rx 表项的活动时间，用于进行老化。
                rxEntry._activeTime = now;

                /**
                 * PARSING: parse packet's conweaveDataTag
                 */
                // 解析数据包的 conweaveDataTag 标签：
                // 获取数据包的路径 ID (pkt_pathId)、时期 (pkt_epoch)、阶段 (pkt_phase)、发送时间戳 (pkt_timestamp_Tx)、TAIL 时间戳 (pkt_timestamp_TAIL)、标志 (pkt_flagData) 以及 IP 包的显式拥塞通告 (pkt_ecnbits)。
                rx_md.pkt_pathId = conweaveDataTag.GetPathId();
                rx_md.pkt_epoch = conweaveDataTag.GetEpoch();
                rx_md.pkt_phase = conweaveDataTag.GetPhase();
                rx_md.pkt_timestamp_Tx = conweaveDataTag.GetTimestampTx();
                rx_md.pkt_timestamp_TAIL = conweaveDataTag.GetTimestampTail();
                rx_md.pkt_flagData = conweaveDataTag.GetFlagData();
                rx_md.pkt_ecnbits = ch.GetIpv4EcnBits(); /* ECN bits */

                /**
                 * ROUND: check epoch: 2(prev), 0(current), or 1(new)
                 */
                // 检查时期 (epoch) 匹配：
                // 如果 Rx 表项的时期小于数据包的时期，则更新 Rx 表项的时期为数据包的时期，并将结果标记为新时期匹配。
                // 如果 Rx 表项的时期大于数据包的时期，则将结果标记为前一时期匹配。
                // 如果 Rx 表项的时期等于数据包的时期，则将结果标记为当前时期匹配。
                if (rxEntry._epoch < rx_md.pkt_epoch) { /* new epoch */
                    rxEntry._epoch = rx_md.pkt_epoch;   /* update to new epoch  */
                    rx_md.resultEpochMatch = 1;
                } else if (rxEntry._epoch > rx_md.pkt_epoch) { /* prev epoch */
                    rx_md.resultEpochMatch = 2;
                } else { /* current epoch */
                    rx_md.resultEpochMatch = 0;
                }

                /** FILTER: if previous epoch, just pass to destination */
                // 如果结果表明前一时期匹配，直接将数据包传递给目标
                if (rx_md.resultEpochMatch == 2) { /* prev epoch */
                    DoSwitchSendToDev(p, ch);      /* immediately send to dst */
                    return;
                }

                /*------- Current or Next Epoch Pkts -------*/

                /**
                 * PHASE: Phase0-Timestamp, Phase, Phase0-Cache
                 */
                // 阶段处理（Phase）：
                // 如果数据包的阶段为 0，则更新 rxEntry 的 phase0TxTime 和 phase0RxTime 时间戳，表示 Phase 0 的发送和接收时间。
                // 获取 rx_md 中 Phase 0 的发送和接收时间戳。
                if (rx_md.pkt_phase == 0) { /* update phase0 timestamp */
                    rxEntry._phase0TxTime = NanoSeconds(rx_md.pkt_timestamp_Tx);
                    rxEntry._phase0RxTime = now;
                }
                rx_md.phase0TxTime = rxEntry._phase0TxTime; /* get TxTime of phase 0 */
                rx_md.phase0RxTime = rxEntry._phase0RxTime; /* get RxTime of phase 0 */

                // 时期匹配为新时期（resultEpochMatch == 1）时的处理
                if (rx_md.resultEpochMatch == 1) { /* new epoch */
                    // TAIL -> set phase=1. Otherwise, set phase 0.
                    // 如果数据包的阶段为 0，则将 rxEntry 的 phase 设置为 0，表示 Phase 0。
                    // 如果数据包的阶段为 1（TAIL 数据包），则将 rxEntry 的 phase 设置为 1。
                    rxEntry._phase = (rx_md.pkt_flagData == ConWeaveDataTag::TAIL) ? 1 : 0;
                    // 检查数据包的阶段是否超前于 rxEntry 的当前阶段，如果是，将 flagOutOfOrder 标记为真。
                    if (rx_md.pkt_phase > rxEntry._phase) { /* check out-of-order */
                        rx_md.flagOutOfOrder = true;
                    }
                    // phase0-cache
                    // 更新 rxEntry 的 phase0Cache，如果数据包的阶段为 0，则将其设置为 true，表示 Phase 0 缓存。
                    rxEntry._phase0Cache = (rx_md.pkt_phase == 0) ? true : false; /* reset/update*/
                    rx_md.flagPhase0Cache = rxEntry._phase0Cache;

                    /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -- */

                    /** DEBUGGING: check there is on-going reordering
                     *  If new epoch progresses but on-going reordering, then current parameter of
                     *  epoch expiration might be too aggressive.
                     *  Try to increase "conweave_txExpiryTime" if this message appears in many
                     *  times.
                     */
                    // 输出调试信息，检查是否存在进行中的重新排序（reordering），如果存在，则输出错误信息。
                    auto voq = m_voqMap.find(rx_md.pkt_flowkey);
                    if (rxEntry._reordering || voq != m_voqMap.end()) {
                        std::cout
                            << __FILE__ << "(" << __LINE__ << "):" << Simulator::Now() << ","
                            << PARSE_FIVE_TUPLE(ch)
                            << " New epoch packet arrives, but reordering is in progress."
                            << " Maybe TxToR made the epoch progress too aggressively."
                            << " If this is frequent, try to increase `cwh_txExpiryTime` value."
                            << std::endl;

                        if (rxEntry._reordering != (voq != m_voqMap.end())) {
                            std::cout
                                << "--> ERROR: reordering status and VOQ status are different..."
                                << std::endl;
                            assert(rxEntry._reordering == (voq != m_voqMap.end()));
                        }
                    }

                    /*- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -- */

                } else {                                               /* current epoch */
                    // 时期匹配为当前时期（resultEpochMatch == 0）时的处理
                    assert(rx_md.resultEpochMatch == 0);               // sanity check
                    if (rx_md.pkt_flagData == ConWeaveDataTag::TAIL) { /* TAIL */
                        // 如果数据包的标志为 TAIL，表示数据包是 TAIL 数据包，根据情况更新 rxEntry 的 phase 为 1。
                        if (!rxEntry._reordering) {
                            rxEntry._phase = 1; /* set phase to 1*/
                        } else {
                            /** NOTE: we set phase to 1 AFTER the current reordering VOQ is flushed
                             */
                        }
                    } else if (rxEntry._phase < rx_md.pkt_phase) { /* check out-of-order */
                        // 检查数据包的阶段是否超前于 rxEntry 的当前阶段，如果是，将 flagOutOfOrder 标记为真。
                        rx_md.flagOutOfOrder = true;
                    }
                    // phase0-cache
                    // 更新 rxEntry 的 phase0Cache，如果数据包的阶段为 0，则将其设置为 true。
                    if (rx_md.pkt_phase == 0) {  // update info
                        rxEntry._phase0Cache = true;
                    }
                    rx_md.flagPhase0Cache = rxEntry._phase0Cache;
                }

                /** TAIL: update or read TAIL TIMESTAMP*/
                // TAIL 时间戳的更新或读取：
                // 如果数据包的标志为 TAIL 或阶段为 1，表示数据包是 TAIL 数据包或处于 Phase 1，更新 rxEntry 的 tailTime 为 TAIL 时间戳，并将 rx_md 中的 tailTime 更新为相同的值。
                // 否则，读取 rxEntry 的 tailTime 并将其保存到 rx_md 中。
                if (rx_md.pkt_flagData == ConWeaveDataTag::TAIL ||
                    rx_md.pkt_phase == 1) { /* update TAIL Time */
                    rxEntry._tailTime = NanoSeconds(rx_md.pkt_timestamp_TAIL);
                    rx_md.tailTime = rxEntry._tailTime.GetNanoSeconds();
                } else { /* read TAIL Time */
                    rx_md.tailTime = rxEntry._tailTime.GetNanoSeconds();
                }

                /** PREDICTION: PREDICTION OF TAIL_ARRIVAL_TIME
                 * 1) Tx Timegap
                 * 2) Either <now + timegap (phase 0)>, or <tx_TAIL + timegap (phase 1)>
                 **/
                // TAIL_ARRIVAL_TIME 的预测：
                // 计算时间差 timegapAtTx，表示当前时间到 Phase 0 的发送时间的时间差。
                // 如果有 Phase 0 的时间信息 (flagPhase0Cache 为真)，则计算期望的 VOQ 刷新时间 timeExpectedToFlush，其中包括 Phase 0 的接收时间、时间差和额外 VOQ 刷新时间。
                // 如果是 Phase 1，且存在数据包的时间戳不按顺序 (flagOutOfOrder 为真)，则计算期望的 VOQ 刷新时间，以当前时间加上时间差和额外 VOQ 刷新时间。
                if (rx_md.flagPhase0Cache) { /* phase0-timestamp is available */
                    rx_md.timegapAtTx = (rx_md.tailTime > rx_md.phase0TxTime.GetNanoSeconds())
                                            ? rx_md.tailTime - rx_md.phase0TxTime.GetNanoSeconds()
                                            : 0;

                    /** DEBUGGING: */
                    if (rx_md.pkt_phase == 1 || rx_md.pkt_flagData == ConWeaveDataTag::TAIL) {
                        if (rx_md.tailTime < rx_md.phase0TxTime.GetNanoSeconds()) {
                            SLB_LOG(PARSE_FIVE_TUPLE(ch)
                                    << "** CONWEAVE WARNING - Though this pkt has tailTime, the "
                                       "tailTime is before Phase0-TxTime");
                            SLB_LOG(PARSE_FIVE_TUPLE(ch)
                                    << "** tailTime:" << rx_md.tailTime
                                    << ",Phase0TxTime:" << rx_md.phase0TxTime.GetNanoSeconds());
                            std::cout << "** CONWEAVE WARNING - Though this pkt has tailTime, the "
                                         "tailTime is before Phase0-TxTime"
                                      << std::endl;
                            exit(1);
                        }
                    }
                } else { /* no RTT info, so use default value */
                    rx_md.timegapAtTx = m_defaultVOQWaitingTime.GetNanoSeconds();
                } /* rx_md.timegapAtTx >= 0 */

                if (rx_md.pkt_phase == 1) {          /* phase 1 */
                    if (rx_md.flagOutOfOrder) {      /* if out-of-order of phase 1 */
                        if (rx_md.flagPhase0Cache) { /* phase0 info exists */
                            rx_md.timeExpectedToFlush =
                                rx_md.phase0RxTime.GetNanoSeconds() + rx_md.timegapAtTx +
                                m_extraVOQFlushTime.GetNanoSeconds(); /* phase0 Rx + timegap */
                        } else {                                      /* no phase0 info */
                            rx_md.timeExpectedToFlush =
                                now.GetNanoSeconds() + rx_md.timegapAtTx +
                                m_extraVOQFlushTime.GetNanoSeconds(); /* now + timegap */
                        }
                    } else { /* not out-of-order */
                        rx_md.timeExpectedToFlush = 0;
                    }
                } else {                                               /* phase 0 */
                    assert(rx_md.flagPhase0Cache);                     // sanity check
                    if (rx_md.pkt_flagData == ConWeaveDataTag::TAIL) { /* TAIL -> Flush VOQ!! */
                        rx_md.timeExpectedToFlush =
                            now.GetNanoSeconds() +
                            1; /* reschedule to flush after 1ns (almost immediately)*/
                    } else {   /* otherwise */
                        rx_md.timeExpectedToFlush = now.GetNanoSeconds() + rx_md.timegapAtTx +
                                                    m_extraVOQFlushTime.GetNanoSeconds();
                    }
                }

                /**
                 * DEBUGGING: print for debugging
                 */
                SLB_LOG(PARSE_FIVE_TUPLE(ch)
                        << "[RxToR] Sw(" << m_switch_id << "),PktEpoch:" << rx_md.pkt_epoch
                        << ",RegEpoch:" << rxEntry._epoch << ",PktPhase:" << rx_md.pkt_phase
                        << ",RegPhase:" << rxEntry._phase << ",DataFlag:" << rx_md.pkt_flagData
                        << ",OoO:" << rx_md.flagOutOfOrder << ",Cch:" << rx_md.flagPhase0Cache
                        << ",Flowkey:" << rx_md.pkt_flowkey);
                SLB_LOG(PARSE_FIVE_TUPLE(ch)
                        << "--> DEBUG - #VOQ:" << m_voqMap.size());  // debugging

                /**
                 * RESCHEDULE: reschedule of VOQ flush time
                 */
                if (rx_md.pkt_phase == 0) {    /* phase 0 -> update if currently reordering */
                    if (rxEntry._reordering) { /* reordering */
                        if (rx_md.pkt_flagData == ConWeaveDataTag::TAIL) {
                            ConWeaveRouting::m_nFlushVOQByTail += 1; /* debugging */
                        }
                        /* new deadline */
                        auto voq = m_voqMap.find(rx_md.pkt_flowkey);
                        assert(voq != m_voqMap.end());  // sanity check

                        rx_md.timeExpectedToFlush =
                            (rx_md.timeExpectedToFlush > now.GetNanoSeconds())
                                ? (rx_md.timeExpectedToFlush - now.GetNanoSeconds())
                                : 0;
                        voq->second.RescheduleFlush(
                            NanoSeconds(rx_md.timeExpectedToFlush)); /* new deadline */
                        SLB_LOG(PARSE_FIVE_TUPLE(ch)
                                << "--> Phase 0 while OoO"
                                << ",VOQ size:" << voq->second.getQueueSize() + 1
                                << ",NextFlushTime:" << NanoSeconds(rx_md.timeExpectedToFlush)
                                << "(TxTimegap:" << rx_md.timegapAtTx
                                << ",Phase0 Tx:" << rx_md.phase0TxTime
                                << ",Phase0 Rx:" << rx_md.phase0RxTime << ")");
                    }
                } else {                          /* phase 1 */
                    if (rx_md.flagOutOfOrder) {   /* out-of-order */
                        rx_md.flagEnqueue = true; /* enqueue */

                        if (rxEntry._reordering) { /* reordering is on-going */
                            auto voq = m_voqMap.find(rx_md.pkt_flowkey);
                            assert(voq != m_voqMap.end());  // sanity check
                            SLB_LOG(PARSE_FIVE_TUPLE(ch)
                                    << "--> SUBSEQ OoO"
                                    << ",VOQ size:" << voq->second.getQueueSize() + 1
                                    << ",No New Deadline Update");

                        } else { /* new out-of-order */
                            rxEntry._reordering = true;
                            ConWeaveVOQ &voq = m_voqMap[rx_md.pkt_flowkey];

                            rx_md.timeExpectedToFlush =
                                (rx_md.timeExpectedToFlush > now.GetNanoSeconds())
                                    ? (rx_md.timeExpectedToFlush - now.GetNanoSeconds())
                                    : 0;
                            voq.Set(rx_md.pkt_flowkey, ch.dip,
                                    NanoSeconds(rx_md.timeExpectedToFlush),
                                    m_extraVOQFlushTime); /* new deadline */
                            voq.m_deleteCallback = MakeCallback(&ConWeaveRouting::DeleteVOQ, this);
                            voq.m_CallbackByVOQFlush =
                                MakeCallback(&ConWeaveRouting::CallbackByVOQFlush, this);
                            voq.m_switchSendToDevCallback =
                                MakeCallback(&ConWeaveRouting::DoSwitchSendToDev, this);
                            SLB_LOG(PARSE_FIVE_TUPLE(ch)
                                    << "--> FIRST OoO"
                                    << ",VOQ size:" << voq.getQueueSize() + 1
                                    << ",NextFlushTime:" << NanoSeconds(rx_md.timeExpectedToFlush)
                                    << "(TxTimegap:" << rx_md.timegapAtTx << ",P0Tx:"
                                    << rx_md.phase0TxTime << ",P0Rx:" << rx_md.phase0RxTime << ")");
                        }
                    } else { /* in-order */
                        assert(rxEntry._reordering == false);
                        assert(m_voqMap.find(rx_md.pkt_flowkey) == m_voqMap.end());
                    }
                }

                /**
                 * NOTIFY: Generate NOTIFY packet if ECN marked
                 */
                if (m_pathAwareRerouting) {
                    if (rx_md.pkt_ecnbits == 0x03) {
                        SendNotify(p, ch, rx_md.pkt_pathId);
                    }
                }

                /**
                 * REPLY: send reply if requested
                 */
                if (rx_md.pkt_flagData == ConWeaveDataTag::INIT) {
                    assert(rx_md.pkt_phase == 0);  // sanity check
                    SendReply(p, ch, ConWeaveReplyTag::INIT, rx_md.pkt_epoch);
                }
                if (rx_md.pkt_flagData == ConWeaveDataTag::TAIL) {
                    assert(rx_md.pkt_phase == 0);  // sanity check
                    SendReply(p, ch, ConWeaveReplyTag::TAIL,
                              rx_md.pkt_epoch);  // send reply
                }

                /**
                 * ENQUEUE: enqueue the packet
                 */
                if (rx_md.flagEnqueue) {
                    m_voqMap[rx_md.pkt_flowkey].Enqueue(p);
                    m_nOutOfOrderPkts++;
                    return;
                }

                /**
                 * SEND: send to end-host
                 */
                DoSwitchSendToDev(p, ch);
                return;
            }

            if (foundConWeaveReplyTag) {  // Received REPLY
                conweaveTxMeta tx_md;
                tx_md.pkt_flowkey = GetFlowKey(ch.dip, ch.sip, ch.udp.dport, ch.udp.sport);
                tx_md.reply_flag = conweaveReplyTag.GetFlagReply();
                tx_md.reply_epoch = conweaveReplyTag.GetEpoch();
                tx_md.reply_phase = conweaveReplyTag.GetPhase();
                auto &txEntry = m_conweaveTxTable[tx_md.pkt_flowkey];

                /**
                 * CHECK: Reply timeout check only when epoch&phase are matched
                 */
                if (tx_md.reply_epoch == txEntry._epoch && tx_md.reply_phase == txEntry._phase) {
                    if (tx_md.reply_flag == ConWeaveReplyTag::INIT) { /* reply of INIT */
                        if (now < txEntry._replyTimer &&
                            txEntry._replyTimer != CW_MAX_TIME) { /* if replied timely */
                            txEntry._stabilized = true;           /* stabilized */
                            txEntry._replyTimer = CW_MAX_TIME;    /* no more timeout */
                            ConWeaveRouting::m_nTimelyInitReplied += 1;
                            SLB_LOG(PARSE_REVERSE_FIVE_TUPLE(ch)
                                    << "[TxToR/GotReplied] Sw(" << m_switch_id << "),PktEpoch:"
                                    << tx_md.reply_epoch << ",PktPhase:" << tx_md.reply_phase
                                    << ",ReplyFlag:" << tx_md.reply_flag << ",ReplyDL"
                                    << txEntry._replyTimer);
                            SLB_LOG(
                                PARSE_REVERSE_FIVE_TUPLE(ch)
                                << "--------------------------------->>> INIT Replied timely!!");
                        } else { /* late reply -> ignore */
                            /* do nothing */
                        }
                    }
                    if (tx_md.reply_flag == ConWeaveReplyTag::TAIL) { /* reply of TAIL */
                        txEntry._stabilized =
                            true;  // out-of-order issue is resolved for this "flowcut"
                        txEntry._replyTimer = CW_MAX_TIME; /* no more timeout */
                        ConWeaveRouting::m_nTimelyTailReplied += 1;
                        SLB_LOG(PARSE_REVERSE_FIVE_TUPLE(ch)
                                << "[TxToR/GotReplied] Sw(" << m_switch_id << "),PktEpoch:"
                                << tx_md.reply_epoch << ",PktPhase:" << tx_md.reply_phase
                                << ",ReplyFlag:" << tx_md.reply_flag << ",ReplyDL"
                                << txEntry._replyTimer);
                        SLB_LOG(PARSE_REVERSE_FIVE_TUPLE(ch)
                                << "-------------------------------------->>> TAIL Replied!!");
                    }
                }
                return;  // drop this reply
            }

            if (m_pathAwareRerouting) {        // Received NOTIFY
                if (foundConWeaveNotifyTag) {  // Received NOTIFY (from ECN)
                    conweaveTxMeta tx_md;
                    auto congestedPathId = conweaveNotifyTag.GetPathId();
                    auto &pathEntry =
                        m_conweavePathTable[DoHash((uint8_t *)&congestedPathId, 4, m_switch_id) %
                                            m_conweavePathTable.size()];
                    SLB_LOG(PARSE_REVERSE_FIVE_TUPLE(ch)
                            << "[TxToR/GotNOTIFY] Sw(" << m_switch_id
                            << ") =-*=-*=-*=-*=-*=-*=-=-*>>> pathId:" << congestedPathId);

                    /**
                     * UPDATE: if entry is expired, overwrite not to use the congested path
                     */
                    pathEntry._pathId = congestedPathId;
                    pathEntry._invalidTime = now + m_pathPauseTime;
                    return;  // drop this NOTIFY
                }
            }

            /**
             * NOTAG: impossible
             */
            SLB_LOG(PARSE_FIVE_TUPLE(ch) << "Sw(" << m_switch_id << "),isToR:" << m_isToR);
            std::cout << __FILE__ << "(" << __LINE__ << "):" << Simulator::Now() << ","
                      << PARSE_FIVE_TUPLE(ch) << std::endl;
            assert(false && "No Tag is impossible");
        }
        // should not reach here (TOR, but neither TxToR nor RxToR)
        SLB_LOG(PARSE_FIVE_TUPLE(ch) << "Sw(" << m_switch_id << "),isToR:" << m_isToR);
        std::cout << __FILE__ << "(" << __LINE__ << "):" << Simulator::Now() << ","
                  << PARSE_FIVE_TUPLE(ch) << std::endl;
        printf(
            "[ERROR] TxToR: %u, RxToR: %u, Current SwitchId: %u, isToR: %u, CwhData: %u, REPLY:%u, "
            "NOTIFY:%u\n",
            srcToRId, dstToRId, m_switch_id, m_isToR, foundConWeaveDataTag, foundConWeaveReplyTag,
            foundConWeaveNotifyTag);
        assert(false);
    }

    /******************************
     *  Non-ToR Switch (Core/Agg) *
     ******************************/
    if (foundConWeaveDataTag) {  // UDP with PathId
        // update hopCount
        uint32_t hopCount = conweaveDataTag.GetHopCount() + 1;
        conweaveDataTag.SetHopCount(hopCount);

        // get outPort
        uint32_t outDev =
            GetOutPortFromPath(conweaveDataTag.GetPathId(), conweaveDataTag.GetHopCount());
        uint32_t qIndex = ch.udp.pg;

        // re-serialize tag
        ConWeaveDataTag temp_tag;
        p->RemovePacketTag(temp_tag);
        p->AddPacketTag(conweaveDataTag);

        // send packet
        SLB_LOG(PARSE_FIVE_TUPLE(ch) << "[NonToR/DATA] Sw(" << m_switch_id << "),"
                                     << "outDev:" << outDev << ",qIndex:" << qIndex
                                     << ",PktEpoch:" << conweaveDataTag.GetEpoch()
                                     << ",PktPhase:" << conweaveDataTag.GetPhase());
        DoSwitchSend(p, ch, outDev, qIndex);
        return;
    }

    // UDP with ECMP
    SLB_LOG("[NonToR/ECMP] Sw(" << m_switch_id << ")," << PARSE_FIVE_TUPLE(ch));
    DoSwitchSendToDev(p, ch);
    return;
}

void ConWeaveRouting::SetConstants(Time extraReplyDeadline, Time extraVOQFlushTime,
                                   Time txExpiryTime, Time defaultVOQWaitingTime,
                                   Time pathPauseTime, bool pathAwareRerouting) {
    NS_LOG_FUNCTION("Setup new parameters at sw" << m_switch_id);
    m_extraReplyDeadline = extraReplyDeadline;
    m_extraVOQFlushTime = extraVOQFlushTime;
    m_txExpiryTime = txExpiryTime;
    m_defaultVOQWaitingTime = defaultVOQWaitingTime;
    m_pathPauseTime = pathPauseTime;
    m_pathAwareRerouting = pathAwareRerouting;
    assert(m_pathAwareRerouting);  // by default, path-aware routing
}

void ConWeaveRouting::SetSwitchInfo(bool isToR, uint32_t switch_id) {
    m_isToR = isToR;
    m_switch_id = switch_id;
}

/** CALLBACK: callback functions  */
void ConWeaveRouting::DoSwitchSend(Ptr<Packet> p, CustomHeader &ch, uint32_t outDev,
                                   uint32_t qIndex) {
    m_switchSendCallback(p, ch, outDev, qIndex);
}
void ConWeaveRouting::DoSwitchSendToDev(Ptr<Packet> p, CustomHeader &ch) {
    m_switchSendToDevCallback(p, ch);
}

// used for callback in VOQ
void ConWeaveRouting::DeleteVOQ(uint64_t flowkey) { m_voqMap.erase(flowkey); }

void ConWeaveRouting::CallbackByVOQFlush(uint64_t flowkey, uint32_t voqSize) {
    SLB_LOG(
        "#################################################################### VOQ FLush, flowkey: "
        << flowkey << ",VOQ size:" << voqSize << "#################");  // debugging

    m_historyVOQSize.push_back(voqSize);  // statistics - track VOQ size
    // update RxEntry
    auto &rxEntry = m_conweaveRxTable[flowkey];  // flowcut entry
    assert(rxEntry._flowkey == flowkey);         // sanity check
    assert(rxEntry._reordering == true);         // sanity check

    rxEntry._reordering = false;
    rxEntry._phase = 1;
}

void ConWeaveRouting::SetSwitchSendCallback(SwitchSendCallback switchSendCallback) {
    m_switchSendCallback = switchSendCallback;
}

void ConWeaveRouting::SetSwitchSendToDevCallback(SwitchSendToDevCallback switchSendToDevCallback) {
    m_switchSendToDevCallback = switchSendToDevCallback;
}

uint32_t ConWeaveRouting::GetVolumeVOQ() {
    uint32_t nTotalPkts = 0;
    for (auto voq : m_voqMap) {
        nTotalPkts += voq.second.getQueueSize();
    }
    return nTotalPkts;
}

void ConWeaveRouting::AgingEvent() {
    auto now = Simulator::Now();

    auto itr1 = m_conweaveTxTable.begin();
    while (itr1 != m_conweaveTxTable.end()) {
        if (now - ((itr1->second)._activeTime) > m_agingTime) {
            itr1 = m_conweaveTxTable.erase(itr1);
        } else {
            ++itr1;
        }
    }

    auto itr2 = m_conweaveRxTable.begin();
    while (itr2 != m_conweaveRxTable.end()) {
        if (now - ((itr2->second)._activeTime) > m_agingTime) {
            itr2 = m_conweaveRxTable.erase(itr2);
        } else {
            ++itr2;
        }
    }

    m_agingEvent = Simulator::Schedule(m_agingTime, &ConWeaveRouting::AgingEvent, this);
}

}  // namespace ns3
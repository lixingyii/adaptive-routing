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

#include "ns3/conga-routing.h"

#include "assert.h"
#include "ns3/assert.h"
#include "ns3/event-id.h"
#include "ns3/ipv4-header.h"
#include "ns3/log.h"
#include "ns3/nstime.h"
#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/settings.h"
#include "ns3/simulator.h"

NS_LOG_COMPONENT_DEFINE("CongaRouting");

namespace ns3 {

/*---- Conga-Tag -----*/

CongaTag::CongaTag() {}
CongaTag::~CongaTag() {}
TypeId CongaTag::GetTypeId(void) {
    static TypeId tid = TypeId("ns3::CongaTag").SetParent<Tag>().AddConstructor<CongaTag>();
    return tid;
}
void CongaTag::SetPathId(uint32_t pathId) { m_pathId = pathId; }
uint32_t CongaTag::GetPathId(void) const { return m_pathId; }
void CongaTag::SetCe(uint32_t ce) { m_ce = ce; }
uint32_t CongaTag::GetCe(void) const { return m_ce; }
void CongaTag::SetFbPathId(uint32_t fbPathId) { m_fbPathId = fbPathId; }
uint32_t CongaTag::GetFbPathId(void) const { return m_fbPathId; }
void CongaTag::SetFbMetric(uint32_t fbMetric) { m_fbMetric = fbMetric; }
uint32_t CongaTag::GetFbMetric(void) const { return m_fbMetric; }

void CongaTag::SetHopCount(uint32_t hopCount) { m_hopCount = hopCount; }
uint32_t CongaTag::GetHopCount(void) const { return m_hopCount; }
TypeId CongaTag::GetInstanceTypeId(void) const { return GetTypeId(); }
uint32_t CongaTag::GetSerializedSize(void) const {
    return sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) +
           sizeof(uint32_t);
}
void CongaTag::Serialize(TagBuffer i) const {
    i.WriteU32(m_pathId);
    i.WriteU32(m_ce);
    i.WriteU32(m_hopCount);
    i.WriteU32(m_fbPathId);
    i.WriteU32(m_fbMetric);
}
void CongaTag::Deserialize(TagBuffer i) {
    m_pathId = i.ReadU32();
    m_ce = i.ReadU32();
    m_hopCount = i.ReadU32();
    m_fbPathId = i.ReadU32();
    m_fbMetric = i.ReadU32();
}
void CongaTag::Print(std::ostream& os) const {
    os << "m_pathId=" << m_pathId;
    os << ", m_ce=" << m_ce;
    os << ", m_hopCount=" << m_hopCount;
    os << ". m_fbPathId=" << m_fbPathId;
    os << ", m_fbMetric=" << m_fbMetric;
}

/*----- Conga-Route ------*/
uint32_t CongaRouting::nFlowletTimeout = 0;
CongaRouting::CongaRouting() {
    m_isToR = false;
    m_switch_id = (uint32_t)-1;

    // set constants
    m_dreTime = Time(MicroSeconds(200));
    m_agingTime = Time(MilliSeconds(10));
    m_flowletTimeout = Time(MicroSeconds(100));
    m_quantizeBit = 3;
    m_alpha = 0.2;
}

// 用于生成一个 64 位的 Flowlet Key
// it defines flowlet's 64bit key (order does not matter)
uint64_t CongaRouting::GetQpKey(uint32_t dip, uint16_t sport, uint16_t dport, uint16_t pg) {
    // ((uint64_t)dip << 32) 将目标 IP 左移 32 位，将其存储在高 32 位的位置。
    // ((uint64_t)sport << 16) 将源端口左移 16 位，将其存储在中间 16 位的位置。
    // (uint64_t)pg 直接存储在中间 16 位的位置。
    // (uint64_t)dport 直接存储在低 16 位的位置。
    return ((uint64_t)dip << 32) | ((uint64_t)sport << 16) | (uint64_t)pg | (uint64_t)dport;
}

TypeId CongaRouting::GetTypeId(void) {
    static TypeId tid =
        TypeId("ns3::CongaRouting").SetParent<Object>().AddConstructor<CongaRouting>();

    return tid;
}

/** CALLBACK: callback functions  */
void CongaRouting::DoSwitchSend(Ptr<Packet> p, CustomHeader& ch, uint32_t outDev, uint32_t qIndex) {
    m_switchSendCallback(p, ch, outDev, qIndex);
}
void CongaRouting::DoSwitchSendToDev(Ptr<Packet> p, CustomHeader& ch) {
    m_switchSendToDevCallback(p, ch);
}

void CongaRouting::SetSwitchSendCallback(SwitchSendCallback switchSendCallback) {
    m_switchSendCallback = switchSendCallback;
}

void CongaRouting::SetSwitchSendToDevCallback(SwitchSendToDevCallback switchSendToDevCallback) {
    m_switchSendToDevCallback = switchSendToDevCallback;
}

void CongaRouting::SetSwitchInfo(bool isToR, uint32_t switch_id) {
    m_isToR = isToR;
    m_switch_id = switch_id;
}

// 用于设置指定 outPort 的链路容量（bitRate），以在 CONGA 路由算法中记录不同出口端口的链路容量
void CongaRouting::SetLinkCapacity(uint32_t outPort, uint64_t bitRate) {
    auto it = m_outPort2BitRateMap.find(outPort);
    // 检查 m_outPort2BitRateMap 中是否已经存在具有相同 outPort 的记录
    if (it != m_outPort2BitRateMap.end()) {
        // already exists, then check matching
        // 验证现有的链路容量是否与新输入的链路容量相匹配
        // 如果存在且不匹配，将生成一个断言（NS_ASSERT_MSG）来指出链路容量不一致的错误
        // 这是为了确保同一出口端口的链路容量始终保持一致
        NS_ASSERT_MSG(it->second == bitRate,
                      "bitrate already exists, but inconsistent with new input");
    } else {
        // 不存在具有相同 outPort 的记录，
        // 函数将添加一个新的条目到 m_outPort2BitRateMap 中，
        // 将 outPort 映射到新的链路容量 bitRate
        m_outPort2BitRateMap[outPort] = bitRate;
    }
}

/* CongaRouting's main function */
void CongaRouting::RouteInput(Ptr<Packet> p, CustomHeader ch) {
    // Packet arrival time
    Time now = Simulator::Now();

    /**
     * NOTE: only DATA UDP is allowed to go through Conga because control packets are prioritized in
     * network and pass with different utility conditions!!
     **/
    if (ch.l3Prot != 0x11) {
        // 数据包不是 UDP 数据包，直接调用 DoSwitchSendToDev 函数将数据包发送到目标设备，绕过 CONGA 路由
        DoSwitchSendToDev(p, ch);
        return;
    }
    assert(ch.l3Prot == 0x11 && "Only supports UDP data packets");

    // Turn on DRE event scheduler if it is not running
    // 启动 DRE 事件调度器
    if (!m_dreEvent.IsRunning()) {
        NS_LOG_FUNCTION("Conga routing restarts dre event scheduling, Switch:" << m_switch_id
                                                                               << now);
        m_dreEvent = Simulator::Schedule(m_dreTime, &CongaRouting::DreEvent, this);
    }

    // Turn on aging event scheduler if it is not running
    // 启动 aging 事件调度器
    if (!m_agingEvent.IsRunning()) {
        NS_LOG_FUNCTION("Conga routing restarts aging event scheduling:" << m_switch_id << now);
        m_agingEvent = Simulator::Schedule(m_agingTime, &CongaRouting::AgingEvent, this);
    }

    // get srcToRId, dstToRId
    assert(Settings::hostIp2SwitchId.find(ch.sip) !=
           Settings::hostIp2SwitchId.end());  // Misconfig of Settings::hostIp2SwitchId - sip"
    assert(Settings::hostIp2SwitchId.find(ch.dip) !=
           Settings::hostIp2SwitchId.end());  // Misconfig of Settings::hostIp2SwitchId - dip"
    uint32_t srcToRId = Settings::hostIp2SwitchId[ch.sip];
    uint32_t dstToRId = Settings::hostIp2SwitchId[ch.dip];

    /** FILTER: Quickly filter intra-pod traffic */
    // 对于来自同一 ToR 的流量，直接发送到目标设备，不经过 CONGA 路由，因为这些流量在同一 ToR 中
    if (srcToRId == dstToRId) {  // do normal routing (only one path)
        DoSwitchSendToDev(p, ch);
        return;
    }

    // it should be not in the same pod
    assert(srcToRId != dstToRId && "Should not be in the same pod");

    // get QpKey to find flowlet
    uint64_t qpkey = GetQpKey(ch.dip, ch.udp.sport, ch.udp.dport, ch.udp.pg);

    // get CongaTag from packet
    // 如果数据包需要经过 CONGA 路由，首先检查是否有 CongaTag 标签。
    CongaTag congaTag;
    bool found = p->PeekPacketTag(congaTag);

    if (m_isToR) {     // ToR switch
        // 如果不存在，表示这是发往目标 ToR 的第一个数据包，表示数据包的发送方位于当前交换机
        if (!found) {  // sender-side
            /*---- add piggyback info to CongaTag ----*/
            // 查找目标 ToR ID (dstToRId) 在 m_congaFromLeafTable 中是否存在，
            // 确保该 ToR 在表中有相关的反馈信息
            auto fbItr = m_congaFromLeafTable.find(dstToRId);
            NS_ASSERT_MSG(fbItr != m_congaFromLeafTable.end(),
                          "dstToRId cannot be found in FromLeafTable");
            auto innerFbItr = (fbItr->second).begin();
            if (!(fbItr->second).empty()) {
                // 如果目标 ToR 的反馈信息存在，从中随机选择一个反馈信息，设置到 congaTag 中
                std::advance(innerFbItr,
                             rand() % (fbItr->second).size());  // uniformly-random feedback
                // set values to new CongaTag
                congaTag.SetHopCount(0);                       // hopCount
                congaTag.SetFbPathId(innerFbItr->first);       // path
                congaTag.SetFbMetric(innerFbItr->second._ce);  // ce
            } else {
                // 如果没有反馈信息可用，则将这些字段设置为 CONGA_NULL，表示没有反馈信息
                // empty (nothing to feedback) then set a dummy
                congaTag.SetHopCount(0);           // hopCount
                congaTag.SetFbPathId(CONGA_NULL);  // path
                congaTag.SetFbMetric(CONGA_NULL);  // ce
            }

            /*---- choosing outPort ----*/
            struct Flowlet* flowlet = NULL;
            auto flowletItr = m_flowletTable.find(qpkey);
            uint32_t selectedPath;

            // 1) when flowlet already exists
            // 数据包对应的 qpkey 已经有与之关联的 Flowlet
            if (flowletItr != m_flowletTable.end()) {
                flowlet = flowletItr->second;
                assert(flowlet != NULL &&
                       "Impossible in normal cases - flowlet is not correctly registered");

                if (now - flowlet->_activeTime <= m_flowletTimeout) {  // no timeout
                    //  Flowlet 已经存在，并且数据包没有超时，
                    // 更新 Flowlet 的信息，包括 activeTime 和已传输的数据包数量
                    // update flowlet info
                    flowlet->_activeTime = now;
                    flowlet->_nPackets++;

                    // update/measure CE of this outPort and add CongaTag
                    // 选择该 Flowlet 的路径作为出口路径。并根据该路径计算出口端口（sender switch 为 0th hop）
                    selectedPath = flowlet->_PathId;
                    uint32_t outPort =
                        GetOutPortFromPath(selectedPath, 0);      // sender switch is 0th hop
                    uint32_t X = UpdateLocalDre(p, ch, outPort);  // update
                    // 测量此出口端口的 CE（Congestion Exposure） 并将其添加到 congaTag 中
                    uint32_t localCe = QuantizingX(outPort, X);   // quantize
                    congaTag.SetCe(localCe);
                    congaTag.SetPathId(selectedPath);

                    p->AddPacketTag(congaTag);
                    NS_LOG_FUNCTION("SenderToR" << m_switch_id << "Flowlet exists"
                                                << "Path/CE/outPort" << selectedPath
                                                << congaTag.GetCe() << outPort << "FbPath/Metric"
                                                << congaTag.GetFbPathId() << congaTag.GetFbMetric()
                                                << now);
                    DoSwitchSend(p, ch, GetOutPortFromPath(selectedPath, congaTag.GetHopCount()),
                                 ch.udp.pg);
                    // return GetOutPortFromPath(selectedPath, congaTag.GetHopCount());
                    return;
                }

                /*---- Flowlet Timeout ----*/
                // NS_LOG_FUNCTION("Flowlet expires, calculate the new port");
                // Flowlet 超时，需要选择新的路径
                selectedPath = GetBestPath(dstToRId, 4);
                CongaRouting::nFlowletTimeout++;

                // update flowlet info
                // 更新 Flowlet 的信息，包括 activatedTime、activeTime 和路径 ID
                flowlet->_activatedTime = now;
                flowlet->_activeTime = now;
                flowlet->_nPackets++;
                flowlet->_PathId = selectedPath;

                // update/add CongaTag
                // 根据新路径计算出口端口的 CE，并将其添加到 congaTag 中
                uint32_t outPort = GetOutPortFromPath(selectedPath, 0);
                uint32_t X = UpdateLocalDre(p, ch, outPort);  // update
                uint32_t localCe = QuantizingX(outPort, X);   // quantize
                congaTag.SetCe(localCe);
                congaTag.SetPathId(selectedPath);
                congaTag.SetHopCount(0);

                p->AddPacketTag(congaTag);
                NS_LOG_FUNCTION("SenderToR" << m_switch_id << "Flowlet exists & Timeout"
                                            << "Path/CE/outPort" << selectedPath << congaTag.GetCe()
                                            << outPort << "FbPath/Metric" << congaTag.GetFbPathId()
                                            << congaTag.GetFbMetric() << now);
                DoSwitchSend(p, ch, outPort, ch.udp.pg);
                // return outPort;
                return;
            }
            // 2) flowlet does not exist, e.g., first packet of flow
            // 数据包没有关联的 Flowlet，表示这是新流的第一个数据包
            // 选择新路径，并创建一个新的 Flowlet，并将其相关信息添加到 congaTag 中
            selectedPath = GetBestPath(dstToRId, 4);
            struct Flowlet* newFlowlet = new Flowlet;
            newFlowlet->_activeTime = now;
            newFlowlet->_activatedTime = now;
            newFlowlet->_nPackets = 1;
            newFlowlet->_PathId = selectedPath;
            m_flowletTable[qpkey] = newFlowlet;

            // update/add CongaTag
            uint32_t outPort = GetOutPortFromPath(selectedPath, 0);
            uint32_t X = UpdateLocalDre(p, ch, outPort);  // update
            uint32_t localCe = QuantizingX(outPort, X);   // quantize
            congaTag.SetCe(localCe);
            congaTag.SetPathId(selectedPath);

            p->AddPacketTag(congaTag);
            NS_LOG_FUNCTION("SenderToR" << m_switch_id << "Flowlet does not exist"
                                        << "Path/CE/outPort" << selectedPath << congaTag.GetCe()
                                        << outPort << "FbPath/Metric" << congaTag.GetFbPathId()
                                        << congaTag.GetFbMetric() << now);
            DoSwitchSend(p, ch, GetOutPortFromPath(selectedPath, congaTag.GetHopCount()),
                         ch.udp.pg);
            // return GetOutPortFromPath(selectedPath, congaTag.GetHopCount());
            return;
        }
        /*---- receiver-side ----*/
        // update CongaToLeaf table
        // 尝试在m_congaToLeafTable中查找具有源ToR ID（srcToRId）的表项，以确保正确查找
        auto toLeafItr = m_congaToLeafTable.find(srcToRId);
        assert(toLeafItr != m_congaToLeafTable.end() && "Cannot find srcToRId from ToLeafTable");
        auto innerToLeafItr = (toLeafItr->second).find(congaTag.GetFbPathId());
        // 通过查看congaTag中的FbPathId和FbMetric（拥塞度反馈路径ID和度量值）来检查是否存在有效的拥塞度反馈信息
        if (congaTag.GetFbPathId() != CONGA_NULL &&
            congaTag.GetFbMetric() != CONGA_NULL) {             // if valid feedback
            // 存在有效的拥塞度反馈信息，代码继续检查是否在toLeafItr->second中找到与FbPathId匹配的记录
            if (innerToLeafItr == (toLeafItr->second).end()) {  // no feedback so far, then create
                // 不存在，则创建一个新的OutpathInfo对象，将拥塞度反馈值FbMetric存储其中，以及更新时间
                OutpathInfo outpathInfo;
                outpathInfo._ce = congaTag.GetFbMetric();
                outpathInfo._updateTime = now;
                (toLeafItr->second)[congaTag.GetFbPathId()] = outpathInfo;
            } else {  // update statistics
                // 已经存在与FbPathId匹配的记录，代码将更新该记录的拥塞度反馈值_ce和更新时间_updateTime
                (innerToLeafItr->second)._ce = congaTag.GetFbMetric();
                (innerToLeafItr->second)._updateTime = now;
            }
        }

        // update CongaFromLeaf table
        // 尝试在m_congaFromLeafTable中查找具有源ToR ID（srcToRId）的表项，以确保正确查找
        auto fromLeafItr = m_congaFromLeafTable.find(srcToRId);
        assert(fromLeafItr != m_congaFromLeafTable.end() &&
               "Cannot find srcToRId from FromLeafTable");
        // 通过查看congaTag中的PathId（路径ID）来检查是否存在与路径ID匹配的记录
        auto innerfromLeafItr = (fromLeafItr->second).find(congaTag.GetPathId());
        if (innerfromLeafItr == (fromLeafItr->second).end()) {  // no data sent so far, then create
            // 不存在与路径ID匹配的记录，代码创建一个新的FeedbackInfo对象，将拥塞度反馈值congaTag.GetCe()存储其中，并记录更新时间
            FeedbackInfo feedbackInfo;
            feedbackInfo._ce = congaTag.GetCe();
            feedbackInfo._updateTime = now;
            (fromLeafItr->second)[congaTag.GetPathId()] = feedbackInfo;
        } else {  // update feedback
            // 已经存在与路径ID匹配的记录，代码将更新该记录的拥塞度反馈值_ce和更新时间_updateTime
            (innerfromLeafItr->second)._ce = congaTag.GetCe();
            (innerfromLeafItr->second)._updateTime = now;
        }

        // remove congaTag from header
        // 从数据包中移除congaTag标签，因为接收方已经处理了该标签的信
        p->RemovePacketTag(congaTag);
        NS_LOG_FUNCTION("ReceiverToR" << m_switch_id << "Path/CE" << congaTag.GetPathId()
                                      << congaTag.GetCe() << "FbPath/Metric"
                                      << congaTag.GetFbPathId() << congaTag.GetFbMetric() << now);
        DoSwitchSendToDev(p, ch);
        // return CONGA_NULL;  // does not matter (outPort number is only 1)
        return;

    } else {  // agg/core switch
        // extract CongaTag
        // 确保CongaTag存在
        assert(found && "If not ToR (leaf), CongaTag should be found");
        // get/update hopCount
        // 用于获取并递增congaTag中的HopCount，表示数据包已经经过了多少跳。这是用于路由决策的一部分
        uint32_t hopCount = congaTag.GetHopCount() + 1;
        congaTag.SetHopCount(hopCount);

        // get outPort
        // 根据congaTag中的路径ID（PathId）和已经递增的hopCount，获取出口端口的信息。
        // 这是用于确定应将数据包发送到哪个端口的关键信息。
        uint32_t outPort = GetOutPortFromPath(congaTag.GetPathId(), hopCount);
        // 调用UpdateLocalDre函数来更新本地DRE（分布式拥塞反馈）信息，其中包括出口端口。X是用于量化拥塞度的度量值
        uint32_t X = UpdateLocalDre(p, ch, outPort);                 // update
        // 使用QuantizingX函数来量化拥塞度，得到本地CE（拥塞度曝露）的值
        uint32_t localCe = QuantizingX(outPort, X);                  // quantize
        // 计算本地CE与从congaTag中获取的CE的最大值，以获取更拥塞的链路的CE。这有助于确保选择最拥塞的路径。
        uint32_t congestedCe = std::max(localCe, congaTag.GetCe());  // get more congested link's CE
        // 更新congaTag的CE字段，将其设置为更拥塞的链路的CE
        congaTag.SetCe(congestedCe);                                 // update CE

        // Re-serialize congaTag
        // 创建一个名为temp_tag的临时CongaTag对象，然后从数据包中删除旧的congaTag。这是为了替换旧的congaTag。
        CongaTag temp_tag;
        //  将更新后的congaTag添加回数据包中，以确保它随着数据包一起传输
        p->RemovePacketTag(temp_tag);
        p->AddPacketTag(congaTag);
        NS_LOG_FUNCTION("Agg/CoreSw" << m_switch_id << "Path/CE/outPort" << congaTag.GetPathId()
                                     << congaTag.GetCe() << outPort << "FbPath/Metric"
                                     << congaTag.GetFbPathId() << congaTag.GetFbMetric() << now);
        DoSwitchSend(p, ch, outPort, ch.udp.pg);
        // return outPort;
        return;
    }
    assert(false && "This should not be occured");
}

// minimize the maximum link utilization
// 找到具有最低拥塞的路径，以便最小化链路利用率
uint32_t CongaRouting::GetBestPath(uint32_t dstToRId, uint32_t nSample) {
    // 从m_congaRoutingTable中查找目标ToR交换机的路径信息
    auto pathItr = m_congaRoutingTable.find(dstToRId);
    assert(pathItr != m_congaRoutingTable.end() && "Cannot find dstToRId from ToLeafTable");
    // 获取目标ToR交换机的路径信息，并创建一个迭代器 innerPathItr 来遍历这些路径
    std::set<uint32_t>::iterator innerPathItr = pathItr->second.begin();
    // 可用的路径数量大于等于 nSample
    if (pathItr->second.size() >= nSample) {  // exception handling
        // 从可用路径中随机选择 nSample 个路径。这是为了防止选择所有路径，而只选择一个子集
        std::advance(innerPathItr, rand() % (pathItr->second.size() - nSample + 1));
    } else {
        // 如果可用的路径数量小于 nSample，则将 nSample 设置为可用路径的数量
        nSample = pathItr->second.size();
        // std::cout << "WARNING - Conga's number of path sampling is higher than available paths.
        // Enforced to reduce nSample:" << nSample << std::endl;
    }

    // path info for remote congestion, <pathId -> pathInfo>
    // 从m_congaToLeafTable中获取目标ToR交换机的路径信息，这些信息用于远程拥塞。
    auto pathInfoMap = m_congaToLeafTable[dstToRId];

    // get min-max path
    // 创建一个std::vector<uint32_t>来存储候选路径，以及一个变量minCongestion，用于跟踪最小的拥塞度
    std::vector<uint32_t> candidatePaths;
    uint32_t minCongestion = CONGA_NULL;
    // 循环遍历 nSample 个路径来评估每个路径的拥塞度，然后筛选出最佳路径
    for (uint32_t i = 0; i < nSample; i++) {
        // get info of path
        // 获取路径的ID（pathId）和与路径关联的路径信息
        uint32_t pathId = *innerPathItr;
        auto innerPathInfo = pathInfoMap.find(pathId);

        // no info means good
        uint32_t localCongestion = 0;
        uint32_t remoteCongestion = 0;

        /* 计算本地拥塞度（localCongestion） */
        // 获取与路径关联的出口端口（outPort）
        auto outPort = GetOutPortFromPath(pathId, 0);  // outPort from pathId (TxToR)

        // local congestion -> get Port Util and quantize it
        // 通过查询DRE映射（m_DreMap）来获取出口端口的拥塞度信息
        auto innerDre = m_DreMap.find(outPort);
        if (innerDre != m_DreMap.end()) {
            // 使用QuantizingX函数来量化拥塞度
            localCongestion = QuantizingX(outPort, innerDre->second);
        }

        /* 计算远程拥塞度（remoteCongestion） */
        // remote congestion
        // 通过查询pathInfoMap来获取与路径关联的远程拥塞度
        if (innerPathInfo != pathInfoMap.end()) {
            remoteCongestion = innerPathInfo->second._ce;
        }

        // get maximum of congestion (local, remote)
        // 计算本地拥塞度和远程拥塞度的最大值，以获取路径的当前拥塞度（CurrCongestion）
        uint32_t CurrCongestion = std::max(localCongestion, remoteCongestion);

        // filter the best path
        // 筛选最低拥塞度的路径：
        // - 如果 minCongestion 大于 CurrCongestion，
        // 则将 minCongestion 更新为 CurrCongestion，
        // 并清空candidatePaths，
        // 然后将当前路径（pathId）添加为候选路径。这表示找到了新的最佳路径。
        if (minCongestion > CurrCongestion) {
            minCongestion = CurrCongestion;
            candidatePaths.clear();
            candidatePaths.push_back(pathId);  // best
        } else if (minCongestion == CurrCongestion) {
            // - 否则，如果 minCongestion 等于 CurrCongestion，
            // 则将当前路径添加到candidatePaths中，
            // 表示当前路径与已知最佳路径的拥塞度相等。
            candidatePaths.push_back(pathId);  // equally good
        }
        std::advance(innerPathItr, 1);
    }
    assert(candidatePaths.size() > 0 && "candidatePaths has no entry");
    // 从candidatePaths中随机选择一个路径作为最佳路径，并将其返回。这样可以确保不会总是选择相同的最佳路径，以便实现负载均衡。
    return candidatePaths[rand() % candidatePaths.size()];  // randomly choose the best path
}

// 用于更新本地DRE（Distributed Rate Estimator）的信息
uint32_t CongaRouting::UpdateLocalDre(Ptr<Packet> p, CustomHeader ch, uint32_t outPort) {
    // 从 m_DreMap 映射中获取特定出口端口 outPort 的当前本地DRE值
    uint32_t X = m_DreMap[outPort];
    // 将当前本地DRE值 X 增加上数据包大小 p->GetSize()，以计算新的DRE值 newX
    uint32_t newX = X + p->GetSize();
    // NS_LOG_FUNCTION("Old X" << X << "New X" << newX << "outPort" << outPort << "Switch" <<
    // m_switch_id << Simulator::Now());
    // 将新的DRE值 newX 存储回 m_DreMap 中，以便下次使用
    m_DreMap[outPort] = newX;
    return newX;
}

uint32_t CongaRouting::GetOutPortFromPath(const uint32_t& path, const uint32_t& hopCount) {
    // 使用 hopCount 作为索引来访问 path 中的字节。
    // 因为 path 是一个 uint32_t 类型的整数，它占用 4 个字节（32位），因此可以按字节索引。
    // 根据 hopCount 的值，这个表达式返回路径中特定跳数的出口端口信息
    return ((uint8_t*)&path)[hopCount];
}

void CongaRouting::SetOutPortToPath(uint32_t& path, const uint32_t& hopCount,
                                    const uint32_t& outPort) {
    ((uint8_t*)&path)[hopCount] = outPort;
}

uint32_t CongaRouting::QuantizingX(uint32_t outPort, uint32_t X) {
    // 通过outPort在名为m_outPort2BitRateMap的映射（std::map）中查找相应的出口端口对应的比特率（bitRate）
    auto it = m_outPort2BitRateMap.find(outPort);
    assert(it != m_outPort2BitRateMap.end() && "Cannot find bitrate of interface");
    uint64_t bitRate = it->second;
    double ratio = static_cast<double>(X * 8) / (bitRate * m_dreTime.GetSeconds() / m_alpha);
    uint32_t quantX = static_cast<uint32_t>(ratio * std::pow(2, m_quantizeBit));
    if (quantX > 3) {
        NS_LOG_FUNCTION("X" << X << "Ratio" << ratio << "Bits" << quantX << Simulator::Now());
    }
    return quantX;
}

void CongaRouting::SetConstants(Time dreTime, Time agingTime, Time flowletTimeout,
                                uint32_t quantizeBit, double alpha) {
    m_dreTime = dreTime;
    m_agingTime = agingTime;
    m_flowletTimeout = flowletTimeout;
    m_quantizeBit = quantizeBit;
    m_alpha = alpha;
}

void CongaRouting::DoDispose() {
    for (auto i : m_flowletTable) {
        delete (i.second);
    }
    m_dreEvent.Cancel();
    m_agingEvent.Cancel();
}

void CongaRouting::DreEvent() {
    std::map<uint32_t, uint32_t>::iterator itr = m_DreMap.begin();
    for (; itr != m_DreMap.end(); ++itr) {
        uint32_t newX = itr->second * (1 - m_alpha);
        itr->second = newX;
    }
    NS_LOG_FUNCTION(Simulator::Now());
    m_dreEvent = Simulator::Schedule(m_dreTime, &CongaRouting::DreEvent, this);
}

void CongaRouting::AgingEvent() {
    auto now = Simulator::Now();
    auto itr = m_congaToLeafTable.begin();  // always non-empty
    for (; itr != m_congaToLeafTable.end(); ++itr) {
        auto innerItr = (itr->second).begin();
        for (; innerItr != (itr->second).end(); ++innerItr) {
            // 如果元素的更新时间超过了m_agingTime，则将该元素的_ce属性设置为0，表示对其进行了”aging”处理
            if (now - (innerItr->second)._updateTime > m_agingTime) {
                (innerItr->second)._ce = 0;
            }
        }
    }

    auto itr2 = m_congaFromLeafTable.begin();
    while (itr2 != m_congaFromLeafTable.end()) {
        auto innerItr2 = (itr2->second).begin();
        while (innerItr2 != (itr2->second).end()) {
            if (now - (innerItr2->second)._updateTime > m_agingTime) {
                innerItr2 = (itr2->second).erase(innerItr2);
            } else {
                ++innerItr2;
            }
        }
        ++itr2;
    }

    auto itr3 = m_flowletTable.begin();
    while (itr3 != m_flowletTable.end()) {
        if (now - ((itr3->second)->_activeTime) > m_agingTime) {
            // delete(itr3->second); // delete pointer
            itr3 = m_flowletTable.erase(itr3);
        } else {
            ++itr3;
        }
    }
    NS_LOG_FUNCTION(Simulator::Now());
    m_agingEvent = Simulator::Schedule(m_agingTime, &CongaRouting::AgingEvent, this);
}

}  // namespace ns3
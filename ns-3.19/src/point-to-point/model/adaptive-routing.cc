#include "ns3/adaptive-routing.h"

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


NS_LOG_COMPONENT_DEFINE("AdaptiveRouting");

namespace ns3 {

/*---- Adaptive-Tag -----*/
AdaptiveTag::AdaptiveTag() {}
AdaptiveTag::~AdaptiveTag() {}
TypeId AdaptiveTag::GetTypeId(void) {
    static TypeId tid = TypeId("ns3::AdaptiveTag").SetParent<Tag>().AddConstructor<AdaptiveTag>();
    return tid;
}
void AdaptiveTag::SetPathId(uint32_t pathId) { m_pathId = pathId; }
uint32_t AdaptiveTag::GetPathId(void) const { return m_pathId; }
void AdaptiveTag::SetHopCount(uint32_t hopCount) { m_hopCount = hopCount; }
uint32_t AdaptiveTag::GetHopCount(void) const { return m_hopCount; }
TypeId AdaptiveTag::GetInstanceTypeId(void) const { return GetTypeId(); }
uint32_t AdaptiveTag::GetSerializedSize(void) const {
    return sizeof(uint32_t) + sizeof(uint32_t);
}
void AdaptiveTag::Serialize(TagBuffer i) const {
    i.WriteU32(m_pathId);
    i.WriteU32(m_hopCount);
}
void AdaptiveTag::Deserialize(TagBuffer i) {
    m_pathId = i.ReadU32();
    m_hopCount = i.ReadU32();
}
void AdaptiveTag::Print(std::ostream& os) const {
    os << "m_pathId=" << m_pathId;
    os << ", m_hopCount=" << m_hopCount;
}

/*----- Adaptive-Routing ------*/
#if PER_FLOWLET
uint32_t AdaptiveRouting::nFlowletTimeout = 0;
#endif
AdaptiveRouting::AdaptiveRouting() {
    m_isToR = false;
    m_switch_id = (uint32_t)-1;

    // set constants
    
    m_defaultVOQWaitingTime = MicroSeconds(200);
    m_extraVOQFlushTime = MicroSeconds(8);        // for uncertainty
#if PER_FLOWLET
    m_agingTime = Time(MilliSeconds(10));
    m_flowletTimeout = Time(MicroSeconds(100));
#endif
}

// 用于生成一个 64 位的 Flow Key
uint64_t AdaptiveRouting::GetQpKey(uint32_t dip, uint16_t sport, uint16_t dport, uint16_t pg) {
    // ((uint64_t)dip << 32) 将目标 IP 左移 32 位，将其存储在高 32 位的位置。
    // ((uint64_t)sport << 16) 将源端口左移 16 位，将其存储在中间 16 位的位置。
    // (uint64_t)pg 直接存储在中间 16 位的位置。
    // (uint64_t)dport 直接存储在低 16 位的位置。
    return ((uint64_t)dip << 32) | ((uint64_t)sport << 16) | (uint64_t)pg | (uint64_t)dport;
}

TypeId AdaptiveRouting::GetTypeId(void) {
    static TypeId tid =
        TypeId("ns3::AdaptiveRouting").SetParent<Object>().AddConstructor<AdaptiveRouting>();

    return tid;
}

/** CALLBACK: callback functions  */
void AdaptiveRouting::DoSwitchSend(Ptr<Packet> p, CustomHeader& ch, uint32_t outDev, uint32_t qIndex) {
    m_switchSendCallback(p, ch, outDev, qIndex);
}
void AdaptiveRouting::DoSwitchSendToDev(Ptr<Packet> p, CustomHeader& ch) {
    m_switchSendToDevCallback(p, ch);
}

void AdaptiveRouting::SetSwitchSendCallback(SwitchSendCallback switchSendCallback) {
    m_switchSendCallback = switchSendCallback;
}

void AdaptiveRouting::SetSwitchSendToDevCallback(SwitchSendToDevCallback switchSendToDevCallback) {
    m_switchSendToDevCallback = switchSendToDevCallback;
}

void AdaptiveRouting::SetSwitchInfo(bool isToR, uint32_t switch_id) {
    m_isToR = isToR;
    m_switch_id = switch_id;
}

/* AdaptiveRouting's main function */
// void AdaptiveRouting::RouteInput(Ptr<Packet> p, CustomHeader ch, double link_utl[128], uint32_t usedEgressPortBytes[128], uint32_t m_maxBufferBytes) {
void AdaptiveRouting::RouteInput(Ptr<Packet> p, CustomHeader ch, const std::vector<Ptr<NetDevice> >& devices, uint32_t usedEgressPortBytes[128], uint32_t m_maxBufferBytes) {
    // Packet 到达时间
    Time now = Simulator::Now();

    // 数据包不是 UDP 数据包，直接调用 DoSwitchSendToDev 函数将数据包发送到目标设备，绕过 AdaptiveRouting 路由
    if (ch.l3Prot != 0x11) {
        DoSwitchSendToDev(p, ch);
        return;
    }
    assert(ch.l3Prot == 0x11 && "Only supports UDP data packets");

#if PER_FLOWLET
    // 启动 aging 事件调度器
    if (!m_agingEvent.IsRunning()) {
        NS_LOG_FUNCTION("Adaptive routing restarts aging event scheduling:" << m_switch_id << now);
        m_agingEvent = Simulator::Schedule(m_agingTime, &AdaptiveRouting::AgingEvent, this);
    }
#endif

    // 获取 srcToRId, dstToRId
    assert(Settings::hostIp2SwitchId.find(ch.sip) != Settings::hostIp2SwitchId.end());
    assert(Settings::hostIp2SwitchId.find(ch.dip) != Settings::hostIp2SwitchId.end());
    uint32_t srcToRId = Settings::hostIp2SwitchId[ch.sip];
    uint32_t dstToRId = Settings::hostIp2SwitchId[ch.dip];
    // std::cout << "源ToR：" << srcToRId << " " << "目的ToR：" << dstToRId << std::endl;

    // 对于来自同一 ToR 的流量，直接发送到目标设备，不经过 AdaptiveRouting 路由，因为这些流量在同一 ToR 中
    if (srcToRId == dstToRId) {  // do normal routing (only one path)
        DoSwitchSendToDev(p, ch);
        // std::cout << "同一 ToR ，发送完成" << std::endl;
        return;
    }
    
    // 源 ToR 和目的 ToR 不应该在一个 pod
    assert(srcToRId != dstToRId && "Should not be in the same pod");

    // 生成查找 flowlet 的 key
    uint64_t qpkey = GetQpKey(ch.dip, ch.udp.sport, ch.udp.dport, ch.udp.pg);

    // 如果数据包需要经过 AdaptiveRouting 路由，首先检查是否有 AdaptiveTag 标签。
    AdaptiveTag adaptiveTag;
    bool found = p->PeekPacketTag(adaptiveTag);

#if PER_FLOWLET
    // 当前 node 为 ToR
    if (m_isToR) {
        // 是否找到 AdaptiveTag ，如果没有找到，表示是发送端
        if (!found) {
            // std::cout<<"当前 node 为 ToR"<<std::endl;
            struct Flowlet* flowlet = NULL;
            // flowlet表中是否存在与该数据包相关的flowlet
            auto flowletItr = m_flowletTable.find(qpkey);
            uint32_t selectedPath;

            // 当 flowlet 已经存在
            if (flowletItr != m_flowletTable.end()) {
                flowlet = flowletItr->second;
                NS_ASSERT_MSG(flowlet != NULL, "Impossible in normal cases - flowlet is not correctly registered");

                // 如果 flowlet 已存在且未超时，
                // 则更新 flowlet 信息，增加数据包计数，
                // 并更新 AdaptiveTag 中的路径信息
                if (now - flowlet->_activeTime <= m_flowletTimeout) {
                    // 更新 flowlet 信息
                    flowlet->_activeTime = now;
                    flowlet->_nPackets++;

                    // 权衡各个可用端口的 pfc 数量和各个队列的 qlen ，选择最优路径，并添加 AdaptiveTag
                    selectedPath = flowlet->_PathId;
                    uint32_t outPort = GetOutPortFromPath(selectedPath, 0);  // 第0跳
                    adaptiveTag.SetPathId(selectedPath);
                    adaptiveTag.SetHopCount(0);

                    p->AddPacketTag(adaptiveTag);
                    NS_LOG_FUNCTION("SenderToR"
                                    << m_switch_id
                                    << "Flowlet exists"
                                    << "Path/outPort" << selectedPath << outPort << now);

                    // 发送 packet
                    DoSwitchSend(p, ch, outPort, ch.udp.pg);
                    // std::cout<<"flowlet 已存在且未超时，ToR发送完成"<<std::endl;
                    return;
                }
                else {
                    // 如果 flowlet 已存在但已超时，
                    // 选择新的路径，并更新 flowlet 信息、增加数据包计数和 adaptiveTag
                    selectedPath = GetBestPath(dstToRId, devices, usedEgressPortBytes, m_maxBufferBytes);
                    // std::cout<<"1"<<std::endl;
                    AdaptiveRouting::nFlowletTimeout++;

                    // 更新 flowlet 信息
                    flowlet->_activatedTime = now;
                    flowlet->_activeTime = now;
                    flowlet->_nPackets++;
                    flowlet->_PathId = selectedPath;

                    // 更新 adaptiveTag
                    uint32_t outPort = GetOutPortFromPath(selectedPath, 0);
                    adaptiveTag.SetPathId(selectedPath);
                    adaptiveTag.SetHopCount(0);

                    p->AddPacketTag(adaptiveTag);
                    NS_LOG_FUNCTION("SenderToR"
                                    << m_switch_id
                                    << "Flowlet exists & Timeout"
                                    << "Path/outPort" << selectedPath << outPort << now);
                    // 发送 packet
                    DoSwitchSend(p, ch, outPort, ch.udp.pg);
                    // std::cout<<"flowlet 已存在但已超时，ToR发送完成"<<std::endl;
                    return;
                }
            }
            else {
                // 如果 flowlet 不存在，
                // 则创建新的 flowlet 、更新 adaptiveTag 和出端口信息，最后返回相应的出端口
                selectedPath = GetBestPath(dstToRId, devices, usedEgressPortBytes, m_maxBufferBytes);
                struct Flowlet* newFlowlet = new Flowlet;
                newFlowlet->_activeTime = now;
                newFlowlet->_activatedTime = now;
                newFlowlet->_nPackets = 1;
                newFlowlet->_PathId = selectedPath;
                m_flowletTable[qpkey] = newFlowlet;

                // 更新 adaptiveTag
                uint32_t outPort = GetOutPortFromPath(selectedPath, 0);
                adaptiveTag.SetPathId(selectedPath);
                adaptiveTag.SetHopCount(0);

                p->AddPacketTag(adaptiveTag);
                NS_LOG_FUNCTION("SenderToR"
                                << m_switch_id
                                << "Flowlet does not exist"
                                << "Path/outPort" << selectedPath << outPort << now);
                DoSwitchSend(p, ch, GetOutPortFromPath(selectedPath, adaptiveTag.GetHopCount()), ch.udp.pg);
                // std::cout<<"flowlet 不存在，ToR发送完成"<<std::endl;
                return;
            }
        }
        else {
            // 如果是接收端，移除 adaptiveTag
            p->RemovePacketTag(adaptiveTag);
            NS_LOG_FUNCTION("ReceiverToR"
                            << m_switch_id
                            << "Path" << adaptiveTag.GetPathId() << now);
            DoSwitchSendToDev(p, ch);
            // std::cout<<"ToR接收端接收完成"<<std::endl;
            return;
        }
    } 
    // 非 ToR 交换机
    else {
        // 检查是否找到 adaptiveTag
        NS_ASSERT_MSG(found, "If not ToR (leaf), adaptiveTag should be found");
        // 获取或更新 hopCount，然后通过 GetOutPortFromPath 函数计算出端口。
        uint32_t hopCount = adaptiveTag.GetHopCount() + 1;
        adaptiveTag.SetHopCount(hopCount);

        // 获取出端口
        uint32_t outPort = GetOutPortFromPath(adaptiveTag.GetPathId(), hopCount);
        
        // 重新序列化 adaptiveTag ，将其添加回数据包中，并返回相应的出端口。
        AdaptiveTag temp_tag;
        p->RemovePacketTag(temp_tag);
        p->AddPacketTag(adaptiveTag);
        NS_LOG_FUNCTION("Agg/CoreSw"
                        << m_switch_id
                        << "Path/outPort" << adaptiveTag.GetPathId() << outPort << now);
        DoSwitchSend(p, ch, outPort, ch.udp.pg);
        // std::cout<<"非ToR发送完成"<<std::endl;
        return;
    }
#else
    if (m_isToR) {
        if (!found) {  // 发送端
            uint32_t selectedPath = GetBestPath(dstToRId, devices, usedEgressPortBytes, m_maxBufferBytes);

            uint32_t outPort = GetOutPortFromPath(selectedPath, 0);
            adaptiveTag.SetPathId(selectedPath);
            adaptiveTag.SetHopCount(0);

            p->AddPacketTag(adaptiveTag);
            NS_LOG_FUNCTION("SenderToR"
                            << m_switch_id
                            << "Flowlet does not exist"
                            << "Path/outPort" << selectedPath << outPort << now);
            DoSwitchSend(p, ch, GetOutPortFromPath(selectedPath, adaptiveTag.GetHopCount()), ch.udp.pg);
            // std::cout<<"flowlet 不存在，ToR发送完成"<<std::endl;
            return;
        }
        else {  // 接收端
            // 如果是接收端，移除 adaptiveTag
            p->RemovePacketTag(adaptiveTag);
            NS_LOG_FUNCTION("ReceiverToR"
                            << m_switch_id
                            << "Path" << adaptiveTag.GetPathId() << now);
            DoSwitchSendToDev(p, ch);
            // std::cout<<"ToR接收端接收完成"<<std::endl;
            return;
        }
    }
    else {  // 非ToR交换机
        // 检查是否找到 adaptiveTag
        NS_ASSERT_MSG(found, "If not ToR (leaf), adaptiveTag should be found");
        // 获取或更新 hopCount，然后通过 GetOutPortFromPath 函数计算出端口。
        uint32_t hopCount = adaptiveTag.GetHopCount() + 1;
        adaptiveTag.SetHopCount(hopCount);

        // 获取出端口
        uint32_t outPort = GetOutPortFromPath(adaptiveTag.GetPathId(), hopCount);
        
        // 重新序列化 adaptiveTag ，将其添加回数据包中，并返回相应的出端口。
        AdaptiveTag temp_tag;
        p->RemovePacketTag(temp_tag);
        p->AddPacketTag(adaptiveTag);
        NS_LOG_FUNCTION("Agg/CoreSw"
                        << m_switch_id
                        << "Path/outPort" << adaptiveTag.GetPathId() << outPort << now);
        DoSwitchSend(p, ch, outPort, ch.udp.pg);
        return;
    }

#endif
    NS_ASSERT_MSG("false", "This should not be occured");
}

// uint32_t AdaptiveRouting::GetBestPath(uint32_t dstToRId, double link_utl[128], uint32_t usedEgressPortBytes[128], uint32_t m_maxBufferBytes) {
uint32_t AdaptiveRouting::GetBestPath(uint32_t dstToRId, const std::vector<Ptr<NetDevice> >& devices, uint32_t usedEgressPortBytes[128], uint32_t m_maxBufferBytes) {
    // 通过目标 ToR 的 ID 在路径表中查找对应的路径集合
    auto pathItr = m_adaptiveRoutingTable.find(dstToRId);
    assert(pathItr != m_adaptiveRoutingTable.end());

    double minCongestion = std::numeric_limits<double>::max();
    double gamma = 0.5;
    unsigned qIndex = 3;

    std::set<uint32_t>::iterator innerPathItr = pathItr->second.begin();
    uint32_t nSample = pathItr->second.size();
    std::vector<uint32_t> candidatePaths;
    uint32_t candidatePath = 0;
    for(uint32_t i = 0; i < nSample; i++) {
        uint32_t pathId = *innerPathItr;
        auto outPort = GetOutPortFromPath(pathId, 0);
        Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(devices[outPort]);
        double pause = device->GetPaused(qIndex) ? 1.0 : 0.0;
        uint32_t qlen = usedEgressPortBytes[outPort];
        double currCongestion = gamma * pause + (1 - gamma) * ((double)qlen / (double)m_maxBufferBytes);
        // std::cout << "当前候选路径为" << pathId << "，" << "当前拥塞程度为" << currCongestion << std::endl;
        if (currCongestion < minCongestion) {
            minCongestion = currCongestion;
            candidatePaths.clear();
            candidatePaths.push_back(pathId);
        }
        else if (currCongestion == minCongestion) {
            candidatePaths.push_back(pathId);
        }
        std::advance(innerPathItr, 1);
    }
    candidatePath = candidatePaths[rand() % candidatePaths.size()];
    // std::cout << "最佳路径为" << candidatePath << "，" << "最小拥塞程度为" << minCongestion << std::endl;
    return candidatePath;
}

uint32_t AdaptiveRouting::GetOutPortFromPath(const uint32_t& path, const uint32_t& hopCount) {
    // 使用 hopCount 作为索引来访问 path 中的字节。
    // 因为 path 是一个 uint32_t 类型的整数，它占用 4 个字节（32位），因此可以按字节索引。
    // 根据 hopCount 的值，这个表达式返回路径中特定跳数的出口端口信息
    return ((uint8_t*)&path)[hopCount];
}

void AdaptiveRouting::SetOutPortToPath(uint32_t& path, const uint32_t& hopCount, const uint32_t& outPort) {
    ((uint8_t*)&path)[hopCount] = outPort;
}

void AdaptiveRouting::SetConstants(Time agingTime, Time flowletTimeout) {
    
#if PER_FLOWLET
    m_agingTime = agingTime;
    m_flowletTimeout = flowletTimeout;
#endif
}

void AdaptiveRouting::DoDispose() {
#if PER_FLOWLET
    for (auto i : m_flowletTable) {
        delete (i.second);
    }
#endif
    m_agingEvent.Cancel();
}

void AdaptiveRouting::AgingEvent() {
    /**
     * @brief This function is just to keep the flowlet table small as possible, to reduce memory overhead.
     */
    NS_LOG_FUNCTION(Simulator::Now());
    auto now = Simulator::Now();
#if PER_FLOWLET
    auto itr = m_flowletTable.begin();
    // 遍历 flowlet 表，检查每个 flowlet 条目的活跃时间是否超过了设定的 aging 时间
    while (itr != m_flowletTable.end()) {
        if (now - ((itr->second)->_activeTime) > m_agingTime) {
            // 如果超过 aging 时间，则从 flowlet 表中删除该条目
            itr = m_flowletTable.erase(itr);
        } else {
            ++itr;
        }
    }
    // 更新 aging 事件，调度下一次 AgingEvent
    m_agingEvent = Simulator::Schedule(m_agingTime, &AdaptiveRouting::AgingEvent, this);
#endif
    
}
}
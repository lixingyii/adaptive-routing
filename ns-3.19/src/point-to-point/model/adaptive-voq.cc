#include "ns3/adaptive-voq.h"

#include "ns3/assert.h"
#include "ns3/adaptive-routing.h"
#include "ns3/ipv4-header.h"
#include "ns3/log.h"
#include "ns3/settings.h"
#include "ns3/simulator.h"

NS_LOG_COMPONENT_DEFINE("AdaptiveVOQ");

namespace ns3 {

AdaptiveVOQ::AdaptiveVOQ() {}
AdaptiveVOQ::~AdaptiveVOQ() {}

std::vector<int> AdaptiveVOQ::m_flushEstErrorhistory; // instantiate static variable

void AdaptiveVOQ::Set(uint64_t flowkey, uint32_t dip, Time timeToFlush, Time extraVOQFlushTime, uint64_t seq) {
    m_flowkey = flowkey;
    m_dip = dip;
    m_extraVOQFlushTime = extraVOQFlushTime;
    m_seq = seq;
    // RescheduleFlush(timeToFlush);
}

void AdaptiveVOQ::Enqueue(uint64_t seq, Ptr<Packet> pkt) { 
    m_buffer[seq] = pkt; 
    // std::cout << "seq为" << seq << "的packet已入缓冲区" << std::endl << std::endl; 
}

void AdaptiveVOQ::FlushAllImmediately() {
    // 遍历队列中的所有数据包
    while (!m_buffer.empty()) {     // for all VOQ pkts
        // std::cout << "当前voq的seq：" << m_seq << std::endl;
        auto it = m_buffer.find(m_seq);
        if (it != m_buffer.end()) {
            // std::cout << "含有seq为" << m_seq << "的packet" << std::endl;
            Ptr<Packet> pkt = it->second;
            // 创建一个自定义头部对象 ch，其中包含 L2、L3、L4 的标识，用于表示数据包的层次结构
            CustomHeader ch(CustomHeader::L2_Header | CustomHeader::L3_Header |
                            CustomHeader::L4_Header);
            pkt->PeekHeader(ch);  // 将数据包的头部信息读取到自定义头部对象 ch 中
            // DoSwitchSendToDev
            m_switchSendToDevCallback(pkt, ch);  // SlbRouting::DoSwitchSendToDev
            // 移除队列头部的数据包，即刚刚处理过的数据包
            m_buffer.erase(it);
            m_seq++;
        }
        else {
            // std::cout << "更新seq" << std::endl << std::endl;
            m_updateSeqCallback(m_flowkey, m_seq);
            return;
        }
    }
    // std::cout << "更新seq" << std::endl;
    // 通过回调函数通知刷新事件的发生，并传递流标识 m_flowkey 和队列大小（数据包个数）
    m_CallbackByVOQFlush(m_flowkey, (uint32_t)m_buffer.size()); /** IMPORTANT: set RxEntry._reordering = false at flushing */
    m_updateSeqCallback(m_flowkey, m_seq);
    // 通过回调函数通知删除当前流标识 m_flowkey 对应的 VOQ，通常涉及到从路由器的 VOQ 映射表中删除相应的条目
    // std::cout << "voq已空，删除voq" << std::endl <<std::endl;
    m_deleteCallback(m_flowkey);  // delete this from SlbRouting::m_voqMap
}

void AdaptiveVOQ::EnforceFlushAll() {
    // 取消下一次计划的刷新事件，以避免在强制刷新时触发计划的刷新
    m_checkFlushEvent.Cancel();
    // 调用 FlushAllImmediately 函数，立即刷新 VOQ 中的所有数据包
    FlushAllImmediately();
}

/**
 * @brief Reschedule flushing timeout
 * @param timeToFlush relative time to flush from NOW
 */
void AdaptiveVOQ::RescheduleFlush(Time timeToFlush) {
    // 检查刷新事件是否已经在运行，即是否已经存在计划的刷新事件
    if (m_checkFlushEvent.IsRunning()) {  // if already exists, reschedule it
        // 获取先前计划的刷新事件的时间戳，用于估计计划的刷新事件和实际强制刷新的时间差
        uint64_t prevEst = m_checkFlushEvent.GetTs();
        if (timeToFlush == 1) {
            // 将估计误差（先前计划刷新时间与当前时间的差减去额外刷新时间）记录到 m_flushEstErrorhistory 中
            m_flushEstErrorhistory.push_back(int(prevEst - Simulator::Now().GetNanoSeconds()) -
                                             m_extraVOQFlushTime.GetNanoSeconds());
        }

        m_checkFlushEvent.Cancel();
    }
    // std::cout << "timeToFlush" << timeToFlush << std::endl;
    m_checkFlushEvent = Simulator::Schedule(Simulator::Now(), &AdaptiveVOQ::EnforceFlushAll, this);
    // EnforceFlushAll();
}

void AdaptiveVOQ::RescheduleFlushImmediately() {
    // 遍历队列中的所有数据包
    while (!m_buffer.empty()) {     // for all VOQ pkts
        // std::cout << "当前voq的seq：" << m_seq << std::endl;
        auto it = m_buffer.find(m_seq);
        if (it != m_buffer.end()) {
            // std::cout << "含有seq为" << m_seq << "的packet" << std::endl;
            Ptr<Packet> pkt = it->second;
            // 创建一个自定义头部对象 ch，其中包含 L2、L3、L4 的标识，用于表示数据包的层次结构
            CustomHeader ch(CustomHeader::L2_Header | CustomHeader::L3_Header |
                            CustomHeader::L4_Header);
            pkt->PeekHeader(ch);  // 将数据包的头部信息读取到自定义头部对象 ch 中
            // DoSwitchSendToDev
            m_switchSendToDevCallback(pkt, ch);  // SlbRouting::DoSwitchSendToDev
            // 移除队列头部的数据包，即刚刚处理过的数据包
            m_buffer.erase(it);
            m_seq++;
        }
        else {
            // std::cout << "更新seq" << std::endl;
            m_updateSeqCallback(m_flowkey, m_seq);
            return;
        }
    }
    // std::cout << "更新seq" << std::endl;
    // 通过回调函数通知刷新事件的发生，并传递流标识 m_flowkey 和队列大小（数据包个数）
    m_CallbackByVOQFlush(m_flowkey, (uint32_t)m_buffer.size()); /** IMPORTANT: set RxEntry._reordering = false at flushing */
    m_updateSeqCallback(m_flowkey, m_seq);
    // 通过回调函数通知删除当前流标识 m_flowkey 对应的 VOQ，通常涉及到从路由器的 VOQ 映射表中删除相应的条目
    // std::cout << "voq已空，删除voq" << std::endl <<std::endl;
    m_deleteCallback(m_flowkey);  // delete this from SlbRouting::m_voqMap
}

bool AdaptiveVOQ::CheckEmpty() { return m_buffer.empty(); }

uint32_t AdaptiveVOQ::getQueueSize() { return (uint32_t)m_buffer.size(); }

}  // namespace ns3
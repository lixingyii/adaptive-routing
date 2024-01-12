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

#include "ns3/conweave-voq.h"

#include "ns3/assert.h"
#include "ns3/conweave-routing.h"
#include "ns3/ipv4-header.h"
#include "ns3/log.h"
#include "ns3/settings.h"
#include "ns3/simulator.h"

NS_LOG_COMPONENT_DEFINE("ConWeaveVOQ");

namespace ns3 {

ConWeaveVOQ::ConWeaveVOQ() {}
ConWeaveVOQ::~ConWeaveVOQ() {}

std::vector<int> ConWeaveVOQ::m_flushEstErrorhistory; // instantiate static variable

void ConWeaveVOQ::Set(uint64_t flowkey, uint32_t dip, Time timeToFlush, Time extraVOQFlushTime) {
    m_flowkey = flowkey;
    m_dip = dip;
    m_extraVOQFlushTime = extraVOQFlushTime;
    RescheduleFlush(timeToFlush);
}

void ConWeaveVOQ::Enqueue(Ptr<Packet> pkt) { m_FIFO.push(pkt); }

void ConWeaveVOQ::FlushAllImmediately() {
    // 通过回调函数通知刷新事件的发生，并传递流标识 m_flowkey 和队列大小（数据包个数）
    m_CallbackByVOQFlush(
        m_flowkey,
        (uint32_t)m_FIFO.size()); /** IMPORTANT: set RxEntry._reordering = false at flushing */
    // 遍历队列中的所有数据包
    while (!m_FIFO.empty()) {     // for all VOQ pkts
        Ptr<Packet> pkt = m_FIFO.front();  // get packet
        // 创建一个自定义头部对象 ch，其中包含 L2、L3、L4 的标识，用于表示数据包的层次结构
        CustomHeader ch(CustomHeader::L2_Header | CustomHeader::L3_Header |
                        CustomHeader::L4_Header);
        pkt->PeekHeader(ch);  // 将数据包的头部信息读取到自定义头部对象 ch 中
        // DoSwitchSendToDev
        m_switchSendToDevCallback(pkt, ch);  // SlbRouting::DoSwitchSendToDev
        // 移除队列头部的数据包，即刚刚处理过的数据包
        m_FIFO.pop();                        // remove this element
    }
    // 通过回调函数通知删除当前流标识 m_flowkey 对应的 VOQ，通常涉及到从路由器的 VOQ 映射表中删除相应的条目
    m_deleteCallback(m_flowkey);  // delete this from SlbRouting::m_voqMap
}

void ConWeaveVOQ::EnforceFlushAll() {
    SLB_LOG(
        "--> *** Finish this epoch by Timeout Enforcement - ConWeaveVOQ Size:" << m_FIFO.size());
    ConWeaveRouting::m_nFlushVOQTotal += 1;  // statistics 用于统计强制刷新的次数
    // 取消下一次计划的刷新事件，以避免在强制刷新时触发计划的刷新
    m_checkFlushEvent.Cancel();               // cancel the next schedule
    // 调用 FlushAllImmediately 函数，立即刷新 VOQ 中的所有数据包
    FlushAllImmediately();                    // flush VOQ immediately
}

/**
 * @brief Reschedule flushing timeout
 * @param timeToFlush relative time to flush from NOW
 */
void ConWeaveVOQ::RescheduleFlush(Time timeToFlush) {
    // 检查刷新事件是否已经在运行，即是否已经存在计划的刷新事件
    if (m_checkFlushEvent.IsRunning()) {  // if already exists, reschedule it

        // 获取先前计划的刷新事件的时间戳，用于估计计划的刷新事件和实际强制刷新的时间差
        uint64_t prevEst = m_checkFlushEvent.GetTs();
        if (timeToFlush.GetNanoSeconds() == 1) {
            // std::cout << (int(prevEst - Simulator::Now().GetNanoSeconds()) -
            //               m_extraVOQFlushTime.GetNanoSeconds())
            //           << std::endl;
            // 将估计误差（先前计划刷新时间与当前时间的差减去额外刷新时间）记录到 m_flushEstErrorhistory 中
            m_flushEstErrorhistory.push_back(int(prevEst - Simulator::Now().GetNanoSeconds()) -
                                             m_extraVOQFlushTime.GetNanoSeconds());
        }

        m_checkFlushEvent.Cancel();
    }
    m_checkFlushEvent = Simulator::Schedule(timeToFlush, &ConWeaveVOQ::EnforceFlushAll, this);
}

bool ConWeaveVOQ::CheckEmpty() { return m_FIFO.empty(); }

uint32_t ConWeaveVOQ::getQueueSize() { return (uint32_t)m_FIFO.size(); }

}  // namespace ns3
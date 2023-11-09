/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2006 Georgia Tech Research Corporation, INRIA
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
 * Author: Yuliang Li <yuliangli@g.harvard.com>
 */

#define __STDC_LIMIT_MACROS 1
#include "ns3/qbb-net-device.h"

#include <stdint.h>
#include <stdio.h>

#include <iostream>
#include <unordered_map>

#include "ns3/assert.h"
#include "ns3/boolean.h"
#include "ns3/cn-header.h"
#include "ns3/custom-header.h"
#include "ns3/data-rate.h"
#include "ns3/double.h"
#include "ns3/drop-tail-queue.h"
#include "ns3/error-model.h"
#include "ns3/flow-id-num-tag.h"
#include "ns3/flow-id-tag.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4.h"
#include "ns3/log.h"
#include "ns3/object-vector.h"
#include "ns3/pause-header.h"
#include "ns3/point-to-point-channel.h"
#include "ns3/pointer.h"
#include "ns3/ppp-header.h"
#include "ns3/qbb-channel.h"
#include "ns3/qbb-header.h"
#include "ns3/random-variable.h"
#include "ns3/rdma-hw.h"
#include "ns3/seq-ts-header.h"
#include "ns3/settings.h"
#include "ns3/simulator.h"
#include "ns3/udp-header.h"
#include "ns3/uinteger.h"

#define MAP_KEY_EXISTS(map, key) (((map).find(key) != (map).end()))

NS_LOG_COMPONENT_DEFINE("QbbNetDevice");

namespace ns3 {

extern std::unordered_map<unsigned, Time> acc_pause_time;

// uint32_t RdmaEgressQueue::ack_q_idx = 3; // 3: Middle priority
uint32_t RdmaEgressQueue::ack_q_idx = 0; // 0: high priority
// RdmaEgressQueue
TypeId RdmaEgressQueue::GetTypeId(void) {
    static TypeId tid =
        TypeId("ns3::RdmaEgressQueue")
            .SetParent<Object>()
            .AddTraceSource("RdmaEnqueue", "Enqueue a packet in the RdmaEgressQueue.",
                            MakeTraceSourceAccessor(&RdmaEgressQueue::m_traceRdmaEnqueue))
            .AddTraceSource("RdmaDequeue", "Dequeue a packet in the RdmaEgressQueue.",
                            MakeTraceSourceAccessor(&RdmaEgressQueue::m_traceRdmaDequeue));
    return tid;
}

RdmaEgressQueue::RdmaEgressQueue() {
    m_rrlast = 0;
    m_qlast = 0;
    m_mtu = 1000;
    m_ackQ = CreateObject<DropTailQueue>();
    m_ackQ->SetAttribute("MaxBytes",
                         UintegerValue(0xffffffff));  // queue limit is on a higher level, not here
}

// 根据传入的队列索引 qIndex 选择相应的队列进行出队操作
Ptr<Packet> RdmaEgressQueue::DequeueQindex(int qIndex) {
    if (qIndex == -1) {  // high prio
        Ptr<Packet> p = m_ackQ->Dequeue();
        m_qlast = -1;
        m_traceRdmaDequeue(p, 0);
        return p;
    }
    if (qIndex >= 0) {  // qp
        Ptr<Packet> p = m_rdmaGetNxtPkt(m_qpGrp->Get(qIndex));
        m_rrlast = qIndex;
        m_qlast = qIndex;
        m_traceRdmaDequeue(p, m_qpGrp->Get(qIndex)->m_pg);
        return p;
    }
    return 0;
}

// 根据当前的队列状态和传入的 paused 数组，确定下一个要处理的队列索引 qIndex
int RdmaEgressQueue::GetNextQindex(bool paused[]) {
    bool found = false;
    uint32_t qIndex;
    // 高优先级队列（ack_q_idx）没有被暂停且队列中有数据包，直接返回 -1，表示处理高优先级队列
    if (!paused[ack_q_idx] && m_ackQ->GetNPackets() > 0) return -1;

    // no pkt in highest priority queue, do rr for each qp
    // 如果高优先级队列没有数据包，或者已经处理完毕，进行循环遍历每个队列，使用轮询（Round Robin）的方式选择下一个队列。
    // 遍历的条件是当前队列未完成（IsQpFinished 返回 false）
    uint32_t fcount = m_qpGrp->GetN();
    for (qIndex = 1; qIndex <= fcount; qIndex++) {
        if (m_qpGrp->IsQpFinished((qIndex + m_rrlast) % fcount)) continue;
        Ptr<RdmaQueuePair> qp = m_qpGrp->Get((qIndex + m_rrlast) % fcount);
        // 条件1：队列没有被暂停，且窗口条件允许发送（未绑定窗口或者启用了 IRN 并且可以发送数据包）
        bool cond1 = !paused[qp->m_pg];
        bool cond_window_allowed =
            (!qp->IsWinBound() && (!qp->irn.m_enabled || qp->CanIrnTransmit(m_mtu)));
        // 条件2：队列中有剩余数据包，且满足窗口条件
        bool cond2 = (qp->GetBytesLeft() > 0 && cond_window_allowed);

        // 条件2不满足，并且队列未完成，设置队列为完成状态
        if (!cond2 && !m_qpGrp->IsQpFinished((qIndex + m_rrlast) % fcount)) {
            if (qp->IsFinishedConst()) {
                m_qpGrp->SetQpFinished((qIndex + m_rrlast) % fcount);
            }
        }
        // 条件1不满足，并且条件2满足，检查队列的下一个可用时间，如果不可用则表示被 PFC 阻塞，记录阻塞时间
        if (!cond1 && cond2) {
            if (m_qpGrp->Get((qIndex + m_rrlast) % fcount)->m_nextAvail.GetTimeStep() >
                Simulator::Now().GetTimeStep()) {
                // not available now
            } else {
                // blocked by PFC
                int32_t flowid = m_qpGrp->Get((qIndex + m_rrlast) % fcount)->m_flow_id;
                if (!MAP_KEY_EXISTS(current_pause_time, flowid))
                    current_pause_time[flowid] = Simulator::Now();
            }
        } else if (cond1 && cond2) {  // 条件1和条件2同时满足，检查队列的下一个可用时间，如果可用则返回当前队列索引
            if (m_qpGrp->Get((qIndex + m_rrlast) % fcount)->m_nextAvail.GetTimeStep() >
                Simulator::Now().GetTimeStep())  // not available now
                continue;
            // Check if the flow has been blocked by PFC
            {
                int32_t flowid = m_qpGrp->Get((qIndex + m_rrlast) % fcount)->m_flow_id;
                if (MAP_KEY_EXISTS(current_pause_time, flowid)) {
                    Time tdiff = Simulator::Now() - current_pause_time[flowid];
                    if (!MAP_KEY_EXISTS(acc_pause_time, flowid))
                        acc_pause_time[flowid] = Seconds(0);
                    acc_pause_time[flowid] = acc_pause_time[flowid] + tdiff;
                    current_pause_time.erase(flowid);
                }
            }
            return (qIndex + m_rrlast) % fcount;
        }
    }
    // 循环结束后没有找到可用的队列，返回 -1024
    return -1024;
}

int RdmaEgressQueue::GetLastQueue() { return m_qlast; }

uint32_t RdmaEgressQueue::GetNBytes(uint32_t qIndex) {
    // 确保输入的队列索引 qIndex 小于当前队列组的数量，以确保不越界
    NS_ASSERT_MSG(qIndex < m_qpGrp->GetN(),
                  "RdmaEgressQueue::GetNBytes: qIndex >= m_qpGrp->GetN()");
    // 获取该队列中剩余的字节数
    return m_qpGrp->Get(qIndex)->GetBytesLeft();
}

uint32_t RdmaEgressQueue::GetFlowCount(void) { return m_qpGrp->GetN(); }

Ptr<RdmaQueuePair> RdmaEgressQueue::GetQp(uint32_t i) { return m_qpGrp->Get(i); }

void RdmaEgressQueue::RecoverQueue(uint32_t i) {
    NS_ASSERT_MSG(i < m_qpGrp->GetN(), "RdmaEgressQueue::RecoverQueue: qIndex >= m_qpGrp->GetN()");
    // 即将下一个要发送的序列号设置为已确认的序列号
    m_qpGrp->Get(i)->snd_nxt = m_qpGrp->Get(i)->snd_una;
}

void RdmaEgressQueue::EnqueueHighPrioQ(Ptr<Packet> p) {
    m_traceRdmaEnqueue(p, 0);
    m_ackQ->Enqueue(p);
}

void RdmaEgressQueue::CleanHighPrio(TracedCallback<Ptr<const Packet>, uint32_t> dropCb) {
    while (m_ackQ->GetNPackets() > 0) {
        Ptr<Packet> p = m_ackQ->Dequeue();
        dropCb(p, 0);
    }
}

/******************
 * QbbNetDevice
 *****************/
NS_OBJECT_ENSURE_REGISTERED(QbbNetDevice);

TypeId QbbNetDevice::GetTypeId(void) {
    static TypeId tid =
        TypeId("ns3::QbbNetDevice")
            .SetParent<PointToPointNetDevice>()
            .AddConstructor<QbbNetDevice>()
            .AddAttribute("QbbEnabled", "Enable the generation of PAUSE packet.",
                          BooleanValue(true), MakeBooleanAccessor(&QbbNetDevice::m_qbbEnabled),
                          MakeBooleanChecker())
            .AddAttribute("QcnEnabled", "Enable the generation of PAUSE packet.",
                          BooleanValue(false), MakeBooleanAccessor(&QbbNetDevice::m_qcnEnabled),
                          MakeBooleanChecker())
            .AddAttribute("DynamicThreshold", "Enable dynamic threshold.", BooleanValue(false),
                          MakeBooleanAccessor(&QbbNetDevice::m_dynamicth), MakeBooleanChecker())
            .AddAttribute("PauseTime", "Number of microseconds to pause upon congestion",
                          UintegerValue(671),  // 65535*(64Bytes/50Gbps)
                          MakeUintegerAccessor(&QbbNetDevice::m_pausetime),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("TxBeQueue", "A queue to use as the transmit queue in the device.",
                          PointerValue(), MakePointerAccessor(&QbbNetDevice::m_queue),
                          MakePointerChecker<Queue>())
            .AddAttribute("RdmaEgressQueue", "A queue to use as the transmit queue in the device.",
                          PointerValue(), MakePointerAccessor(&QbbNetDevice::m_rdmaEQ),
                          MakePointerChecker<Object>())
            .AddTraceSource("QbbEnqueue", "Enqueue a packet in the QbbNetDevice.",
                            MakeTraceSourceAccessor(&QbbNetDevice::m_traceEnqueue))
            .AddTraceSource("QbbDequeue", "Dequeue a packet in the QbbNetDevice.",
                            MakeTraceSourceAccessor(&QbbNetDevice::m_traceDequeue))
            .AddTraceSource("QbbDrop", "Drop a packet in the QbbNetDevice.",
                            MakeTraceSourceAccessor(&QbbNetDevice::m_traceDrop))
            .AddTraceSource("RdmaQpDequeue", "A qp dequeue a packet.",
                            MakeTraceSourceAccessor(&QbbNetDevice::m_traceQpDequeue))
            .AddTraceSource("QbbPfc", "get a PFC packet. 0: resume, 1: pause",
                            MakeTraceSourceAccessor(&QbbNetDevice::m_tracePfc));

    return tid;
}

QbbNetDevice::QbbNetDevice() {
    NS_LOG_FUNCTION(this);
    m_ecn_source = new std::vector<ECNAccount>;
    for (uint32_t i = 0; i < qCnt; i++) {
        m_paused[i] = false;
    }

    m_rdmaEQ = CreateObject<RdmaEgressQueue>();
}

QbbNetDevice::~QbbNetDevice() { NS_LOG_FUNCTION(this); }

void QbbNetDevice::DoDispose() {
    NS_LOG_FUNCTION(this);

    PointToPointNetDevice::DoDispose();
}

void QbbNetDevice::TransmitComplete(void) {
    NS_LOG_FUNCTION(this);
    NS_ASSERT_MSG(m_txMachineState == BUSY, "Must be BUSY if transmitting");
    m_txMachineState = READY;
    NS_ASSERT_MSG(m_currentPkt != 0, "QbbNetDevice::TransmitComplete(): m_currentPkt zero");
    m_phyTxEndTrace(m_currentPkt);
    m_currentPkt = 0;
    DequeueAndTransmit();
}

// 设备从队列中取出数据包并开始传输的关键逻辑
void QbbNetDevice::DequeueAndTransmit(void) {
    NS_LOG_FUNCTION(this);
    // 链路断开 (m_linkUp 为 false) 或者传输状态为忙碌 (m_txMachineState 为 BUSY)，则直接返回，不执行传输
    if (!m_linkUp) return;                 // if link is down, return
    if (m_txMachineState == BUSY) return;  // Quit if channel busy
    Ptr<Packet> p;
    // 对于服务器节点
    if (m_node->GetNodeType() == 0) {  // server
        // 通过调用m_rdmaEQ->GetNextQindex方法获取下一个要传输的队列索引
        int qIndex = m_rdmaEQ->GetNextQindex(m_paused);
        // 如果存在要传输的数据包，根据队列索引执行相应逻辑，包括高优先级队列和普通队列
        if (qIndex != -1024) {
            if (qIndex == -1) {  // high prio
                p = m_rdmaEQ->DequeueQindex(qIndex);
                m_traceDequeue(p, 0);
                TransmitStart(p);
                return;
            }
            // a qp dequeue a packet
            Ptr<RdmaQueuePair> lastQp = m_rdmaEQ->GetQp(qIndex);
            p = m_rdmaEQ->DequeueQindex(qIndex);

            // transmit
            m_traceQpDequeue(p, lastQp);
            TransmitStart(p);

            // update for the next avail time
            m_rdmaPktSent(lastQp, p, m_tInterframeGap);
        } else {  // no packet to send
            // 没有要传输的数据包，检查是否存在 PFC (Pause Frame Control) 的限制，如果有，则根据 PFC 的时间调度下一次传输任务
            NS_LOG_INFO("PAUSE prohibits send at node " << m_node->GetId());
            Time t = Simulator::GetMaximumSimulationTime();
            bool valid = false;
            for (uint32_t i = 0; i < m_rdmaEQ->GetFlowCount(); i++) {
                // 遍历所有的 RDMA 队列对（m_rdmaEQ->GetFlowCount()），
                // 获取每个队列对应的 RDMA 队列指针，
                // 并检查是否有剩余字节数（qp->GetBytesLeft() > 0）且下一个可用时间在当前模拟时间之后
                Ptr<RdmaQueuePair> qp = m_rdmaEQ->GetQp(i);
                if (qp->GetBytesLeft() == 0 || qp->m_nextAvail <= Simulator::Now()) continue;
                // 更新 t 为这些队列中最小的下一个可用时间，并将 valid 设为 true
                t = Min(qp->m_nextAvail, t);
                valid = true;
            }
            // 存在满足条件的队列，且下一次传输任务时间 m_nextSend 已经过期，
            // 且 t 在有效范围内（小于模拟时间的最大值且大于当前模拟时间），则调度下一次传输任务。
            if (valid && m_nextSend.IsExpired() && t < Simulator::GetMaximumSimulationTime() &&
                t > Simulator::Now()) {
                m_nextSend = Simulator::Schedule(t - Simulator::Now(),
                                                 &QbbNetDevice::DequeueAndTransmit, this);
            }
        }
        return;
    } else {                               // switch, doesn't care about qcn, just send
        // 使用循环队列（Round-Robin）方式从队列中取出一个数据包（p = m_queue->DequeueRR(m_paused)）
        p = m_queue->DequeueRR(m_paused);  // this is round-robin
        // 成功取出数据包
        if (p != 0) {
            // 记录数据包的信息
            m_snifferTrace(p);
            m_promiscSnifferTrace(p);
            // 处理 IPv4 头部，获取协议类型，并移除头部
            Ipv4Header h;
            Ptr<Packet> packet = p->Copy();
            uint16_t protocol = 0;
            ProcessHeader(packet, protocol);
            packet->RemoveHeader(h);
            FlowIdTag t;
            // 获取队列的索引（qIndex = m_queue->GetLastQueue()）
            uint32_t qIndex = m_queue->GetLastQueue();
            if (qIndex == 0) {  // this is a pause or cnp, send it immediately!
                // 队列索引为 0，
                // 表示这是一个暂停（pause）或 CNP（Congestion Notification Packet），
                // 则立即通知交换机出队，并移除流标记（m_node->SwitchNotifyDequeue 和 p->RemovePacketTag(t)）
                m_node->SwitchNotifyDequeue(m_ifIndex, qIndex, p);
                p->RemovePacketTag(t);
            } else {
                // 队列索引不为 0，则同样通知交换机出队，并移除流标记
                m_node->SwitchNotifyDequeue(m_ifIndex, qIndex, p);
                p->RemovePacketTag(t);
            }
            m_traceDequeue(p, qIndex);
            TransmitStart(p);
            return;
        } else {  // No queue can deliver any packet
            // 无法取出数据包
            NS_LOG_INFO("PAUSE prohibits send at node " << m_node->GetId());
            // 当前节点是服务器节点且启用了 QCN（m_node->GetNodeType() == 0 && m_qcnEnabled），则检查是否由于 QCN 流控导致没有数据包可发送。
            if (m_node->GetNodeType() == 0 &&
                m_qcnEnabled) {  // nothing to send, possibly due to qcn flow control, if so
                                 // reschedule sending
                // 重新调度发送任务
                // 遍历所有 RDMA 队列对，获取每个队列对应的 RDMA 队列指针，并检查是否有剩余字节数且下一个可用时间在当前模拟时间之后。
                // 如果满足条件，更新 t 为这些队列中最小的下一个可用时间
                Time t = Simulator::GetMaximumSimulationTime();
                for (uint32_t i = 0; i < m_rdmaEQ->GetFlowCount(); i++) {
                    Ptr<RdmaQueuePair> qp = m_rdmaEQ->GetQp(i);
                    if (qp->GetBytesLeft() == 0) continue;
                    t = Min(qp->m_nextAvail, t);
                }
                // 存在满足条件的队列，且下一次传输任务时间 m_nextSend 已经过期，且 t 在有效范围内（小于模拟时间的最大值且大于当前模拟时间），则调度下一次传输任务
                if (m_nextSend.IsExpired() && t < Simulator::GetMaximumSimulationTime() &&
                    t > Simulator::Now()) {
                    m_nextSend = Simulator::Schedule(t - Simulator::Now(),
                                                     &QbbNetDevice::DequeueAndTransmit, this);
                }
            }
        }
    }
    return;
}

// 当某个队列（由 qIndex 指定）被暂停（PAUSE）后，调用 Resume 函数进行恢复
void QbbNetDevice::Resume(unsigned qIndex) {
    NS_LOG_FUNCTION(this << qIndex);
    NS_ASSERT_MSG(m_paused[qIndex], "Must be PAUSEd");
    // 将对应队列的暂停状态标志设置为 false，表示该队列不再暂停（m_paused[qIndex] = false）
    m_paused[qIndex] = false;
    NS_LOG_INFO("Node " << m_node->GetId() << " dev " << m_ifIndex << " queue " << qIndex
                        << " resumed at " << Simulator::Now().GetSeconds());
    DequeueAndTransmit();
}

void QbbNetDevice::Receive(Ptr<Packet> packet) {
    NS_LOG_FUNCTION(this << packet);
    // 检查链路状态，如果链路处于关闭状态，则记录丢弃该数据包的跟踪信息（m_traceDrop(packet, 0)）并返回
    if (!m_linkUp) {
        m_traceDrop(packet, 0);
        return;
    }

    // 如果存在接收错误模型并且该模型指示数据包损坏，根据错误模型的设置执行相应的处理。如果需要丢弃损坏的数据包，记录丢弃跟踪信息并返回
    if (m_receiveErrorModel && m_receiveErrorModel->IsCorrupt(packet)) {
        //
        // If we have an error model and it indicates that it is time to lose a
        // corrupted packet, don't forward this packet up, let it go.
        //
        m_phyRxDropTrace(packet);
        return;
    }

    // 执行数据包的 MAC 接收跟踪
    m_macRxTrace(packet);
    // 使用 CustomHeader 解析数据包中的自定义头，该头包含 L2、L3 和 L4 层的信息。getInt 被设置为 1，表示解析 INT 头部
    CustomHeader ch(CustomHeader::L2_Header | CustomHeader::L3_Header | CustomHeader::L4_Header);
    ch.getInt = 1;  // parse INT header
    packet->PeekHeader(ch);
    // 如果数据包的 L3 协议字段（ch.l3Prot）为 0xFE，表示该数据包是 PFC（Pause Frame Control）包。根据 PFC 的信息执行相应的操作
    if (ch.l3Prot == 0xFE) {  // PFC
        if (!m_qbbEnabled) return;
        unsigned qIndex = ch.pfc.qIndex;
        // std::cerr << "PFC!!" << std::endl;
        if (ch.pfc.time > 0) {
            // 如果 PFC 包携带了暂停时间（ch.pfc.time > 0），
            // 则记录 PFC 跟踪信息，将对应队列标记为暂停状态，并安排在一定时间后调用 Resume 函数以恢复队列传输
            m_tracePfc(1);
            m_paused[qIndex] = true;
            Simulator::Cancel(m_resumeEvt[qIndex]);
            m_resumeEvt[qIndex] =
                Simulator::Schedule(MicroSeconds(ch.pfc.time), &QbbNetDevice::Resume, this, qIndex);
        } else {
            // 如果 PFC 包的时间为 0，则取消之前安排的 Resume 事件，立即调用 Resume 函数恢复队列
            m_tracePfc(0);
            Simulator::Cancel(m_resumeEvt[qIndex]);
            Resume(qIndex);
        }
    } else {                              // non-PFC packets (data, ACK, NACK, CNP...)
        if (m_node->GetNodeType() > 0) {  // switch
            // 	如果节点是交换机（m_node->GetNodeType() > 0），将数据包标记上相应的流 ID，并将数据包发送给节点进行处理
            packet->AddPacketTag(FlowIdTag(m_ifIndex));
            m_node->SwitchReceiveFromDevice(this, packet, ch);
        } else {  // NIC
            // 如果节点是 NIC，将数据包发送给 RdmaHw 处理。根据 RdmaHw 的处理结果，可能执行 MPI 接收操作（DoMpiReceive(packet)）
            // send to RdmaHw
            int ret = m_rdmaReceiveCb(packet, ch);
            // TODO we may based on the ret do something
            if (ret == 0) DoMpiReceive(packet);
        }
    }
    return;
}

bool QbbNetDevice::Send(Ptr<Packet> packet, const Address &dest, uint16_t protocolNumber) {
    NS_ASSERT_MSG(false, "QbbNetDevice::Send not implemented yet\n");
    return false;
}

bool QbbNetDevice::SwitchSend(uint32_t qIndex, Ptr<Packet> packet, CustomHeader &ch) {
    m_macTxTrace(packet);
    m_traceEnqueue(packet, qIndex);
    m_queue->Enqueue(packet, qIndex);
    DequeueAndTransmit();
    return true;
}

uint32_t QbbNetDevice::SendPfc(uint32_t qIndex, uint32_t type) {
    // 检查是否启用 Qbb 功能，如果未启用，则直接返回 0
    if (!m_qbbEnabled) return 0;
    // 创建一个大小为 0 的 Packet 对象，表示 PFC 包
    Ptr<Packet> p = Create<Packet>(0);
    // 创建 PauseHeader（暂停帧头），其中包括暂停时间、队列索引和当前队列的字节数。将 PauseHeader 添加到 Packet 对象中
    PauseHeader pauseh((type == 0 ? m_pausetime : 0), m_queue->GetNBytes(qIndex), qIndex);
    p->AddHeader(pauseh);
    // 准备 IPv4 头部，设置协议字段为 0xFE 表示 PFC，源地址为设备的本地地址，目标地址为广播地址（“255.255.255.255”）。
    // 设置其他 IPv4 头部字段，包括负载大小、TTL（Time to Live）等，并将 IPv4 头部添加到 Packet 对象中。
    Ipv4Header ipv4h;  // Prepare IPv4 header
    ipv4h.SetProtocol(0xFE);
    ipv4h.SetSource(m_node->GetObject<Ipv4>()->GetAddress(m_ifIndex, 0).GetLocal());
    ipv4h.SetDestination(Ipv4Address("255.255.255.255"));
    ipv4h.SetPayloadSize(p->GetSize());
    ipv4h.SetTtl(1);
    ipv4h.SetIdentification(UniformVariable(0, 65536).GetValue());
    p->AddHeader(ipv4h);
    // 添加以太网头部，设置以太网类型为 0x800 表示 IPv4
    AddHeader(p, 0x800);
    // 创建 CustomHeader，并通过 PeekHeader 获取 Packet 的头部信息
    CustomHeader ch(CustomHeader::L2_Header | CustomHeader::L3_Header | CustomHeader::L4_Header);
    p->PeekHeader(ch);
    SwitchSend(0, p, ch);
    // 返回 PFC 包的暂停时间（如果 PFC 类型为 0），否则返回 0
    return (type == 0 ? m_pausetime : 0);
}

bool QbbNetDevice::Attach(Ptr<QbbChannel> ch) {
    NS_LOG_FUNCTION(this << &ch);
    m_channel = ch;
    m_channel->Attach(this);
    NotifyLinkUp();
    return true;
}

bool QbbNetDevice::TransmitStart(Ptr<Packet> p) {
    NS_LOG_FUNCTION(this << p);
    NS_LOG_LOGIC("UID is " << p->GetUid() << ")");
    //
    // This function is called to start the process of transmitting a packet.
    // We need to tell the channel that we've started wiggling the wire and
    // schedule an event that will be executed when the transmission is complete.
    //
    NS_ASSERT_MSG(m_txMachineState == READY, "Must be READY to transmit");
    m_txMachineState = BUSY;
    m_currentPkt = p;
    m_phyTxBeginTrace(m_currentPkt);
    Time txTime = Seconds(m_bps.CalculateTxTime(p->GetSize()));
    Time txCompleteTime = txTime + m_tInterframeGap;
    NS_LOG_LOGIC("Schedule TransmitCompleteEvent in " << txCompleteTime.GetSeconds() << "sec");
    Simulator::Schedule(txCompleteTime, &QbbNetDevice::TransmitComplete, this);

    bool result = m_channel->TransmitStart(p, this, txTime);
    if (result == false) {
        m_phyTxDropTrace(p);
    }
    return result;
}

Ptr<Channel> QbbNetDevice::GetChannel(void) const { return m_channel; }

bool QbbNetDevice::IsQbb(void) const { return true; }

void QbbNetDevice::NewQp(Ptr<RdmaQueuePair> qp) {
    qp->m_nextAvail = Simulator::Now();
    DequeueAndTransmit();
}
void QbbNetDevice::ReassignedQp(Ptr<RdmaQueuePair> qp) { DequeueAndTransmit(); }
void QbbNetDevice::TriggerTransmit(void) { DequeueAndTransmit(); }

void QbbNetDevice::SetQueue(Ptr<BEgressQueue> q) {
    NS_LOG_FUNCTION(this << q);
    m_queue = q;
}

Ptr<BEgressQueue> QbbNetDevice::GetQueue() { return m_queue; }

Ptr<RdmaEgressQueue> QbbNetDevice::GetRdmaQueue() { return m_rdmaEQ; }

void QbbNetDevice::RdmaEnqueueHighPrioQ(Ptr<Packet> p) {
    m_traceEnqueue(p, 0);
    m_rdmaEQ->EnqueueHighPrioQ(p);
}

void QbbNetDevice::TakeDown() {
    // TODO: delete packets in the queue, set link down
    if (m_node->GetNodeType() == 0) {
        // clean the high prio queue
        m_rdmaEQ->CleanHighPrio(m_traceDrop);
        // notify driver/RdmaHw that this link is down
        m_rdmaLinkDownCb(this);
    } else {  // switch
        // clean the queue
        for (uint32_t i = 0; i < qCnt; i++) m_paused[i] = false;
        while (1) {
            Ptr<Packet> p = m_queue->DequeueRR(m_paused);
            if (p == 0) break;
            m_traceDrop(p, m_queue->GetLastQueue());
        }
        // TODO: Notify switch that this link is down
    }
    m_linkUp = false;
}

void QbbNetDevice::UpdateNextAvail(Time t) {
    if (!m_nextSend.IsExpired() && t < m_nextSend.GetTs()) {
        Simulator::Cancel(m_nextSend);
        Time delta = t < Simulator::Now() ? Time(0) : t - Simulator::Now();
        m_nextSend = Simulator::Schedule(delta, &QbbNetDevice::DequeueAndTransmit, this);
    }
}
}  // namespace ns3

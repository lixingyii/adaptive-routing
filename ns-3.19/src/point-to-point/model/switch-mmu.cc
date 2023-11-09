#include "switch-mmu.h"

#include <fstream>
#include <iostream>

#include "ns3/assert.h"
#include "ns3/boolean.h"
#include "ns3/broadcom-node.h"
#include "ns3/double.h"
#include "ns3/global-value.h"
#include "ns3/log.h"
#include "ns3/object-vector.h"
#include "ns3/packet.h"
#include "ns3/random-variable.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"

NS_LOG_COMPONENT_DEFINE("SwitchMmu");
namespace ns3 {
TypeId SwitchMmu::GetTypeId(void) {
    static TypeId tid =
        TypeId("ns3::SwitchMmu")
            .SetParent<Object>()
            .AddConstructor<SwitchMmu>()
            .AddAttribute("IngressAlpha", "Broadcom Ingress alpha", DoubleValue(0.0625),
                          MakeDoubleAccessor(&SwitchMmu::m_pg_shared_alpha_cell),
                          MakeDoubleChecker<double>())
            .AddAttribute("EgressAlpha", "Broadcom Egress alpha", DoubleValue(1.),
                          MakeDoubleAccessor(&SwitchMmu::m_pg_shared_alpha_cell_egress),
                          MakeDoubleChecker<double>())
            .AddAttribute("DynamicThreshold", "Broadcom Egress alpha", BooleanValue(true),
                          MakeBooleanAccessor(&SwitchMmu::SetDynamicThreshold,
                                              &SwitchMmu::GetDynamicThreshold),
                          MakeBooleanChecker())
            .AddAttribute(
                "MaxTotalBufferPerPort",
                "Maximum buffer size of MMU per port in bytes (12-port switch: 12 * 375kB = 4.5MB)",
                UintegerValue(375 * 1000),
                MakeUintegerAccessor(&SwitchMmu::SetMaxBufferBytesPerPort,
                                     &SwitchMmu::GetMaxBufferBytesPerPort),
                MakeUintegerChecker<uint32_t>())
            .AddAttribute(
                "ActivePortCnt", "Number of active switch ports", UintegerValue(12),
                MakeUintegerAccessor(&SwitchMmu::SetActivePortCnt, &SwitchMmu::GetActivePortCnt),
                MakeUintegerChecker<uint32_t>())
            .AddAttribute(
                "PGHeadroomLimit", "Headroom Limit per PG",
                UintegerValue(12500 + 2 * MTU),  // 2*(LinkDelay*Bandwidth+MTU) 2*1us*450Gbps+2*MTU
                MakeUintegerAccessor(&SwitchMmu::SetPgHdrmLimit, &SwitchMmu::GetPgHdrmLimit),
                MakeUintegerChecker<uint32_t>());
    return tid;
}
SwitchMmu::SwitchMmu(void) {
    // Default buffer size: 375kB per active ports
    // 12-port switch: 12 * 375kB = 4.5MB
    // 32-port switch: 32 * 375kB = 12MB
    // m_maxBufferBytes = 4500 * 1000; //Originally: 9MB Current:4.5MB
    m_uniform_random_var.SetStream(0);

    // dynamic threshold
    m_dynamicth = false;

    InitSwitch();
}

void SwitchMmu::InitSwitch(void) {
    m_maxBufferBytes = m_staticMaxBufferBytes ? m_staticMaxBufferBytes
                                              : (m_maxBufferBytesPerPort * m_activePortCnt);
    m_usedTotalBytes = 0;

    // 根据是否启用动态阈值（m_dynamicth），设置不同的阈值
    if (m_dynamicth) {  // 如果启用动态阈值，那么 m_pg_shared_limit_cell 和 m_port_max_shared_cell 将设置为 m_maxBufferBytes，表示不再遵循静态阈值
        m_pg_shared_limit_cell = m_maxBufferBytes;  // using dynamic threshold, we don't respect the
                                                    // static thresholds anymore
        m_port_max_shared_cell = m_maxBufferBytes;
    } else {  // 否则，将设置静态阈值
        m_pg_shared_limit_cell = 20 * MTU;    // max buffer for an ingress pg
        m_port_max_shared_cell = 4800 * MTU;  // max buffer for an ingress port
    }

    for (uint32_t i = 0; i < pCnt; i++)  // port 0 is not used
    {
        m_usedIngressPortBytes[i] = 0;
        m_usedEgressPortBytes[i] = 0;
        for (uint32_t j = 0; j < qCnt; j++) {
            m_usedIngressPGBytes[i][j] = 0;
            m_usedIngressPGHeadroomBytes[i][j] = 0;
            m_usedEgressQMinBytes[i][j] = 0;
            m_usedEgressQSharedBytes[i][j] = 0;
        }
    }
    for (int i = 0; i < 4; i++) {
        m_usedIngressSPBytes[i] = 0;
        m_usedEgressSPBytes[i] = 0;
    }
    // ingress params
    m_buffer_cell_limit_sp = 4000 * MTU;  // ingress sp buffer threshold
    // m_buffer_cell_limit_sp_shared=4000*MTU; //ingress sp buffer shared threshold, nonshare ->
    // share
    m_pg_min_cell = MTU;    // ingress pg guarantee
    m_port_min_cell = MTU;  // ingress port guarantee
    // m_pg_hdrm_limit = 103000; //2*10us*40Gbps+2*1.5kB //106 * MTU; //ingress pg headroom // set
    // dynamically
    m_port_max_pkt_size = 100 * MTU;  // ingress global headroom
    uint32_t total_m_pg_hdrm_limit = 0;
    for (int i = 0; i < m_activePortCnt; i++) total_m_pg_hdrm_limit += m_pg_hdrm_limit[i];
    m_buffer_cell_limit_sp =
        m_maxBufferBytes - total_m_pg_hdrm_limit -
        (m_activePortCnt)*std::max(qCnt * m_pg_min_cell,
                                   m_port_min_cell);  // 12000 * MTU; //ingress sp buffer threshold
    // still needs reset limits..
    m_port_min_cell_off = 4700 * MTU;
    m_pg_shared_limit_cell_off = m_pg_shared_limit_cell - 2 * MTU;

    // egress params
    m_op_buffer_shared_limit_cell =
        m_maxBufferBytes -
        (m_activePortCnt)*std::max(
            qCnt * m_pg_min_cell,
            m_port_min_cell);  // m_maxBufferBytes; //per egress sp limit, //maxBufferBytes(375KB *
                               // activePortNumber) - activePortNumber * (MTU * 8) ~ 367KB *
                               // activePortNumber
    m_op_uc_port_config_cell = m_maxBufferBytes;  // per egress port limit
    m_q_min_cell = 1 + MTU;
    m_op_uc_port_config1_cell = m_maxBufferBytes;

    m_port_shared_alpha_cell = 128;  // not used for now. not sure whether this is used on switches
    m_pg_shared_alpha_cell_off_diff = 16;
    m_port_shared_alpha_cell_off_diff = 16;
    m_log_start = 2.1;
    m_log_end = 2.2;
    m_log_step = 0.00001;
}

// 用于检查数据包是否可以被接受并入队到交换机的入口缓冲区
bool SwitchMmu::CheckIngressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize) {
    // 断言 m_pg_shared_alpha_cell 大于零，确保 Alpha 参数合法
    NS_ASSERT(m_pg_shared_alpha_cell > 0);

    // 检查是否入口缓冲区已满，
    // 即已使用的总字节数 m_usedTotalBytes 加上当前数据包大小 psize 是否大于最大缓冲区大小 m_maxBufferBytes
    if (m_usedTotalBytes + psize > m_maxBufferBytes)  // buffer full, usually should not reach here.
    {
        std::cerr << "WARNING: Drop because ingress buffer full\n";
        return false;
    }
    // 如果缓冲区没有满，方法继续检查数据包是否满足最小保证要求。
    // 这是通过比较已使用的端口级别和队列级别缓冲区大小与最小保证参数进行的
    /*
    如果数据包大小 psize 加上已使用的队列级别缓冲区大小 m_usedIngressPGBytes[port][qIndex] 超过了队列的最小保证 m_pg_min_cell，
    或者数据包大小与已使用的端口级别缓冲区大小 m_usedIngressPortBytes[port] 超过了端口的最小保证 m_port_min_cell，
    则表示数据包将使用共享缓冲区
    */
    if (m_usedIngressPGBytes[port][qIndex] + psize > m_pg_min_cell &&
        m_usedIngressPortBytes[port] + psize >
            m_port_min_cell)  // exceed guaranteed, use share buffer
    {
        /*
        在使用共享缓冲区之前，
        方法会检查是否已使用的入口 SP 缓冲区大小 m_usedIngressSPBytes[GetIngressSP(port, qIndex)] 是否超过了入口 SP 缓冲区的阈值 m_buffer_cell_limit_sp。
        如果超过了这个阈值，表示头部空间已经被使用
        */
        if (m_usedIngressSPBytes[GetIngressSP(port, qIndex)] >
            m_buffer_cell_limit_sp)  // check if headroom is already being used
        {
            /*
            如果头部空间已经被使用，
            方法会继续检查是否数据包大小 psize 加上已使用的队列级别缓冲区大小 m_usedIngressPGHeadroomBytes[port][qIndex] 是否超过了队列的头部限制 m_pg_hdrm_limit[port]。
            如果超过了头部限制，表示头部空间已满，且数据包无法进入头部空间
            */
            if (m_usedIngressPGHeadroomBytes[port][qIndex] + psize >
                m_pg_hdrm_limit[port])  // exceed headroom space
            {
                if (m_PFCenabled) {
                    std::cerr << "WARNING: Drop because ingress headroom full:"
                              << m_usedIngressPGHeadroomBytes[port][qIndex] << "\t"
                              << m_pg_hdrm_limit << "\n";
                }
                return false;
            }
        }
    }
    return true;
}

// 用于检查数据包是否可以被接受并出队到交换机的出口缓冲区
bool SwitchMmu::CheckEgressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize) {
    // 断言 m_pg_shared_alpha_cell_egress 大于零，确保 Alpha 参数合法
    NS_ASSERT(m_pg_shared_alpha_cell_egress > 0);

    // PFC OFF Nothing
    bool threshold = true;
    /*
    如果已使用的出口 SP 缓冲区大小 m_usedEgressSPBytes[GetEgressSP(port, qIndex)] 加上数据包大小 psize 超过了 SP 缓冲区的阈值 m_op_buffer_shared_limit_cell，
    则表示数据包无法进入 SP 缓冲区
    */
    if (m_usedEgressSPBytes[GetEgressSP(port, qIndex)] + psize >
        m_op_buffer_shared_limit_cell)  // exceed the sp limit
    {
        std::cerr << "WARNING: Drop because egress SP buffer full (exceed the sp limit), "
                  << Simulator::Now() << std::endl;
        return false;
    }
    /*
    如果已使用的出口端口级缓冲区大小 m_usedEgressPortBytes[port] 加上数据包大小 psize 超过了端口级缓冲区的阈值 m_op_uc_port_config_cell，
    则表示数据包无法进入端口级缓冲区
    */
    if (m_usedEgressPortBytes[port] + psize > m_op_uc_port_config_cell)  // exceed the port limit
    {
        std::cerr << "WARNING: Drop because egress Port buffer full (exceed the port limit), "
                  << Simulator::Now() << std::endl;
        return false;
    }
    /*
    如果已使用的出口队列级共享缓冲区大小 m_usedEgressQSharedBytes[port][qIndex] 加上数据包大小 psize 超过了队列级共享缓冲区的阈值 m_op_uc_port_config1_cell，
    则表示数据包无法进入队列级共享缓冲区
    */
    if (m_usedEgressQSharedBytes[port][qIndex] + psize >
        m_op_uc_port_config1_cell)  // exceed the queue limit
    {
        std::cerr << "WARNING: Drop because egress Q buffer full (exceed the queue limit), "
                  << Simulator::Now() << std::endl;
        return false;
    }

    /*
    比较已使用的队列级共享缓冲区大小与动态阈值 m_pg_shared_alpha_cell_egress 的乘积与可用共享缓冲区大小
    */
    if ((double)m_usedEgressQSharedBytes[port][qIndex] + psize >
        m_pg_shared_alpha_cell_egress * ((double)m_op_buffer_shared_limit_cell -
                                         m_usedEgressSPBytes[GetEgressSP(port, qIndex)])) {
#if (SLB_DEBUG == true)
        // std::cerr << "WARNING: Drop because egress DT threshold exceed, Port:" << port
        //           << ", Queue:" << qIndex
        //           << ", QlenInfo:"
        //           << ((double)m_usedEgressQSharedBytes[port][qIndex] + psize) << " > "
        //           << (m_pg_shared_alpha_cell_egress * ((double)m_op_buffer_shared_limit_cell -
        //           m_usedEgressSPBytes[GetEgressSP(port, qIndex)]))
        //           << ". Natural if not using PFC"
        //           << std::endl;
#endif
        threshold = false;
        // drop because it exceeds threshold
    }
    return threshold;
}

// 用于更新入口缓冲区的使用情况，当数据包成功接受并入队时，将记录相应的缓冲区使用情况
void SwitchMmu::UpdateIngressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize) {
    // 首先将已使用的总缓冲区字节数 m_usedTotalBytes 增加数据包的大小 psize，以反映总的缓冲区使用情况
    m_usedTotalBytes += psize;  // count total buffer usage
    // 将已使用的入口 SP 缓冲区字节数 m_usedIngressSPBytes[GetIngressSP(port, qIndex)] 递增数据包的大小 psize，表示 SP 缓冲区的使用情况
    m_usedIngressSPBytes[GetIngressSP(port, qIndex)] += psize;
    // 将已使用的入口端口级缓冲区字节数 m_usedIngressPortBytes[port] 递增数据包的大小 psize，表示端口级缓冲区的使用情况
    m_usedIngressPortBytes[port] += psize;
    // 将已使用的入口队列级缓冲区字节数 m_usedIngressPGBytes[port][qIndex] 递增数据包的大小 psize，表示队列级缓冲区的使用情况
    m_usedIngressPGBytes[port][qIndex] += psize;
    // 检查是否开始使用headroom buffer
    // 如果已使用的入口 SP 缓冲区字节数 m_usedIngressSPBytes[GetIngressSP(port, qIndex)] 超过了 SP 缓冲区的阈值 m_buffer_cell_limit_sp，
    // 则表示开始使用headroom buffer
    if (m_usedIngressSPBytes[GetIngressSP(port, qIndex)] >
        m_buffer_cell_limit_sp)  // begin to use headroom buffer
    {
        m_usedIngressPGHeadroomBytes[port][qIndex] += psize;
    }
}

void SwitchMmu::UpdateEgressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize) {
    /*
    检查队列级缓冲区 m_usedEgressQMinBytes[port][qIndex] 是否还有足够的空间容纳数据包，
    如果还有剩余的空间可以容纳数据包，则将数据包的大小 psize 添加到队列级缓冲区，
    并相应地更新端口级缓冲区 m_usedEgressPortBytes[port]。
    */
    if (m_usedEgressQMinBytes[port][qIndex] + psize < m_q_min_cell)  // guaranteed
    {
        m_usedEgressQMinBytes[port][qIndex] += psize;
        m_usedEgressPortBytes[port] = m_usedEgressPortBytes[port] + psize;
        return;
    } else {
        /*
        如果队列级缓冲区已经达到其最小容量 m_q_min_cell，
        表示不再有空间容纳更多数据包，
        那么需要将数据包添加到共享池（Shared Pool）
        */
        /*
        2 case
        First, when there is left space in q_min_cell, and we should use remaining space in
        q_min_cell and add rest to the shared_pool Second, just adding to shared pool
        */
        /*
        如果队列级缓冲区中仍有一些空闲空间，
        方法将剩余的空闲空间添加到共享池 m_usedEgressQSharedBytes[port][qIndex] 中。
        此操作会更新队列级缓冲区、端口级缓冲区和 SP 级缓冲区的使用情况。
        然后，方法将数据包的大小 psize 添加到共享池，同时更新端口级缓冲区和 SP 级缓冲区的使用情况。
        */
        if (m_usedEgressQMinBytes[port][qIndex] != m_q_min_cell) {
            m_usedEgressQSharedBytes[port][qIndex] = m_usedEgressQSharedBytes[port][qIndex] +
                                                     psize + m_usedEgressQMinBytes[port][qIndex] -
                                                     m_q_min_cell;
            m_usedEgressPortBytes[port] =
                m_usedEgressPortBytes[port] +
                psize;  //+ m_usedEgressQMinBytes[port][qIndex] - m_q_min_cell ;
            m_usedEgressSPBytes[GetEgressSP(port, qIndex)] =
                m_usedEgressSPBytes[GetEgressSP(port, qIndex)] + psize +
                m_usedEgressQMinBytes[port][qIndex] - m_q_min_cell;
            m_usedEgressQMinBytes[port][qIndex] = m_q_min_cell;

        } 
        /*如果队列级缓冲区已经达到最小容量，
        并且没有剩余空间，
        那么方法将数据包的大小 psize 直接添加到共享池，
        并相应地更新端口级缓冲区和 SP 级缓冲区的使用情况
        */
        else {
            m_usedEgressQSharedBytes[port][qIndex] += psize;
            m_usedEgressPortBytes[port] += psize;
            m_usedEgressSPBytes[GetEgressSP(port, qIndex)] += psize;
        }
    }
}

// 用于从入口缓冲区中删除数据包并相应地更新缓冲区使用情况
void SwitchMmu::RemoveFromIngressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize) {
    // 首先检查是否存在足够的数据包以从缓冲区中删除。
    // 如果缓冲区中的总字节数小于 psize，则输出警告并将 m_usedTotalBytes 设置为 psize，以表示此时缓冲区已经空了
    if (m_usedTotalBytes < psize) {
        m_usedTotalBytes = psize;
        std::cerr << "Warning : Illegal Remove" << std::endl;
    }
    // 接着，方法检查 SP（Service Pool）级别的缓冲区，
    // 以确保其大小不小于 psize。如果 SP 级别的缓冲区小于 psize，
    // 则输出警告并将 SP 缓冲区的大小设置为 psize
    if (m_usedIngressSPBytes[GetIngressSP(port, qIndex)] < psize) {
        m_usedIngressSPBytes[GetIngressSP(port, qIndex)] = psize;
        std::cerr << "Warning : Illegal Remove" << std::endl;
    }
    // 方法还检查端口级缓冲区和队列级缓冲区，以确保它们的大小不小于 psize，并在需要时执行相同的操作
    if (m_usedIngressSPBytes[GetIngressSP(port, qIndex)] < psize) {
        m_usedIngressSPBytes[GetIngressSP(port, qIndex)] = psize;
        std::cerr << "Warning : Illegal Remove" << std::endl;
    }
    if (m_usedIngressPortBytes[port] < psize) {
        m_usedIngressPortBytes[port] = psize;
        std::cerr << "Warning : Illegal Remove" << std::endl;
    }
    if (m_usedIngressPGBytes[port][qIndex] < psize) {
        m_usedIngressPGBytes[port][qIndex] = psize;
        std::cerr << "Warning : Illegal Remove" << std::endl;
    }
    // 从缓冲区使用情况中减去 psize 的值，以表示已经从缓冲区中删除了数据包。
    // 这会涉及更新总字节数、SP 级别字节数、端口级字节数、队列级字节数和队列级 headroom 字节数
    m_usedTotalBytes -= psize;
    m_usedIngressSPBytes[GetIngressSP(port, qIndex)] -= psize;
    m_usedIngressPortBytes[port] -= psize;
    m_usedIngressPGBytes[port][qIndex] -= psize;
    // 检查队列级 headroom 字节数，以确保它不小于零。
    // 如果 headroom 字节数小于 psize，则将其设置为零，表示 headroom 空间已被释放
    if ((double)m_usedIngressPGHeadroomBytes[port][qIndex] - psize > 0)
        m_usedIngressPGHeadroomBytes[port][qIndex] -= psize;
    else
        m_usedIngressPGHeadroomBytes[port][qIndex] = 0;
}

// 用于从出口缓冲区中移除数据包并更新相应的缓冲区使用情况
void SwitchMmu::RemoveFromEgressAdmission(uint32_t port, uint32_t qIndex, uint32_t psize) {
    // 检查数据包是否已经在队列级保证缓冲区 q_min_cell 中。
    // 如果数据包在 q_min_cell 中，那么它会从该队列级缓冲区中减去 psize 的大小，以确保不会超过保证限制
    if (m_usedEgressQMinBytes[port][qIndex] < m_q_min_cell)  // guaranteed
    {
        if (m_usedEgressQMinBytes[port][qIndex] < psize) {
            std::cerr << "STOP overflow\n";
        }
        m_usedEgressQMinBytes[port][qIndex] -= psize;
        m_usedEgressPortBytes[port] -= psize;
        return;
    } else {
        /*
        2 case
        First, when packet was using both qminbytes and qsharedbytes we should substract from each
        one Second, just subtracting shared pool
        */

        // first case
        // 第一种情况是数据包之前同时使用了 q_min_cell 和 q_shared_bytes
        if (m_usedEgressQMinBytes[port][qIndex] == m_q_min_cell &&
            m_usedEgressQSharedBytes[port][qIndex] < psize) {
            // 从 q_min_cell 中减去 psize 的大小，并减少 q_shared_bytes 和对应的 SP 缓冲区大小，以确保不会超过保证限制
            m_usedEgressQMinBytes[port][qIndex] = m_usedEgressQMinBytes[port][qIndex] +
                                                  m_usedEgressQSharedBytes[port][qIndex] - psize;
            m_usedEgressSPBytes[GetEgressSP(port, qIndex)] =
                m_usedEgressSPBytes[GetEgressSP(port, qIndex)] -
                m_usedEgressQSharedBytes[port][qIndex];
            m_usedEgressQSharedBytes[port][qIndex] = 0;
            if (m_usedEgressPortBytes[port] < psize) {
                std::cerr << "STOP overflow\n";
            }
            m_usedEgressPortBytes[port] -= psize;

        } 
        // 数据包只是从 q_shared_bytes 中使用了空间
        else {
            // 从 q_shared_bytes 中减去 psize 的大小，并相应地减少端口级缓冲区和 SP 缓冲区的大小，以确保不会超过相关的限制
            // 检查端口级缓冲区、SP 缓冲区和队列级 SP 缓冲区的大小，以确保它们不会小于零。如果任何一个缓冲区的大小小于 psize，则会输出错误信息
            if (m_usedEgressQSharedBytes[port][qIndex] < psize ||
                m_usedEgressPortBytes[port] < psize ||
                m_usedEgressSPBytes[GetEgressSP(port, qIndex)] < psize) {
                std::cerr << "STOP overflow\n";
            }
            m_usedEgressQSharedBytes[port][qIndex] -= psize;
            m_usedEgressPortBytes[port] -= psize;
            m_usedEgressSPBytes[GetEgressSP(port, qIndex)] -= psize;
        }
        return;
    }
}

void SwitchMmu::GetPauseClasses(uint32_t port, uint32_t qIndex, bool pClasses[]) {
    if (port > m_activePortCnt) {
        std::cerr << "ERROR: port is " << port << std::endl;
    }
    if (m_dynamicth) {  // 采用动态阈值
        for (uint32_t i = 0; i < qCnt; i++) {  // 遍历所有队列（qCnt）以确定哪些队列应该被暂停
            pClasses[i] = false;
            // 检查该队列的已使用缓冲区大小（m_usedIngressPGBytes[port][i]）是否小于等于 m_pg_min_cell 和 m_port_min_cell 的和
            // 如果是，表示队列未超出保证限制，可以继续
            if (m_usedIngressPGBytes[port][i] <= m_pg_min_cell + m_port_min_cell) continue;

            // std::cerr << "BCM : Used=" << m_usedIngressPGBytes[port][i] << ", thresh=" <<
            // m_pg_shared_alpha_cell*((double)m_buffer_cell_limit_sp -
            // m_usedIngressSPBytes[GetIngressSP(port, qIndex)]) + m_pg_min_cell+m_port_min_cell <<
            // std::endl;

            // 该队列的已使用缓冲区大小减去 m_pg_min_cell 和 m_port_min_cell 是否大于动态阈值（m_pg_shared_alpha_cell）乘以可用的共享缓冲区大小。
            // 如果是，表示队列应该被暂停
            // 如果队列的头空间（m_usedIngressPGHeadroomBytes[port][qIndex]）不为零，表示队列应该被暂停
            if ((double)m_usedIngressPGBytes[port][i] - m_pg_min_cell - m_port_min_cell >
                    m_pg_shared_alpha_cell * ((double)m_buffer_cell_limit_sp -
                                              m_usedIngressSPBytes[GetIngressSP(port, qIndex)]) ||
                m_usedIngressPGHeadroomBytes[port][qIndex] != 0) {
                pClasses[i] = true;
            }
        }
    } else {  // 采用静态阈值
        // 如果端口级已使用缓冲区大小（m_usedIngressPortBytes[port]）大于静态阈值（m_port_max_shared_cell），表示整个端口都应该被暂停
        if (m_usedIngressPortBytes[port] > m_port_max_shared_cell)  // pause the whole port
        {
            for (uint32_t i = 0; i < qCnt; i++) {
                pClasses[i] = true;
            }
            return;
        } else {
            for (uint32_t i = 0; i < qCnt; i++) {
                pClasses[i] = false;
            }
        }
        // 方法将遍历队列，并将每个队列的 pClasses 根据是否超出队列级共享限制（m_pg_shared_limit_cell）进行设置
        if (m_usedIngressPGBytes[port][qIndex] > m_pg_shared_limit_cell) {
            pClasses[qIndex] = true;
        }
    }
    return;
}

bool SwitchMmu::GetResumeClasses(uint32_t port, uint32_t qIndex) {
    // 检查给定的端口和队列是否已被暂停
    if (!paused[port][qIndex]) return false;
    if (m_dynamicth) {  // 采用动态阈值
        // 计算一个阈值，即已使用缓冲区大小减去 m_pg_min_cell 和 m_port_min_cell 后再减去动态阈值偏移（m_pg_shared_alpha_cell_off_diff），
        // 然后与动态阈值（m_pg_shared_alpha_cell）乘以可用的共享缓冲区大小相比较
        // 同时，检查队列的头空间（m_usedIngressPGHeadroomBytes[port][qIndex]）是否为零
        // 已使用缓冲区大小小于计算的阈值，并且队列的头空间为零，则返回 true，表示应该取消流控
        if ((double)m_usedIngressPGBytes[port][qIndex] - m_pg_min_cell - m_port_min_cell <
                m_pg_shared_alpha_cell * ((double)m_buffer_cell_limit_sp -
                                          m_usedIngressSPBytes[GetIngressSP(port, qIndex)] -
                                          m_pg_shared_alpha_cell_off_diff) &&
            m_usedIngressPGHeadroomBytes[port][qIndex] == 0) {
            return true;
        }
    } else {  // 采用静态阈值
        // 检查队列的已使用缓冲区大小是否小于队列级共享限制（m_pg_shared_limit_cell_off）
        // 检查端口级已使用缓冲区大小是否小于端口级最小限制（m_port_min_cell_off）
        if (m_usedIngressPGBytes[port][qIndex] < m_pg_shared_limit_cell_off &&
            m_usedIngressPortBytes[port] < m_port_min_cell_off) {
            return true;
        }
    }
    return false;
}

uint32_t SwitchMmu::GetIngressSP(uint32_t port, uint32_t pgIndex) {
    if (pgIndex == 1)
        return 1;
    else
        return 0;
}

uint32_t SwitchMmu::GetEgressSP(uint32_t port, uint32_t qIndex) {
    if (qIndex == 0)
        return 0;
    else
        return 1;
}

// 用于确定是否应该发送CN（Congestion Notification）帧
bool SwitchMmu::ShouldSendCN(uint32_t ifindex, uint32_t qIndex) {
    // 具有最高优先级的队列，不应发送CN帧
    if (qIndex == 0)  // qidx=0 as highest priority
        return false;

    // 检查队列的已使用缓冲区大小（m_usedEgressQSharedBytes[ifindex][qIndex]）是否大于 kmax[ifindex]
    // 如果已使用缓冲区大小超过 kmax[ifindex]，则返回 true，表示应该发送CN帧
    if (m_usedEgressQSharedBytes[ifindex][qIndex] > kmax[ifindex]) {
        return true;
    } else if (m_usedEgressQSharedBytes[ifindex][qIndex] > kmin[ifindex] &&
               kmin[ifindex] != kmax[ifindex]) {
        // 已使用缓冲区大小未超过 kmax[ifindex]
        // 检查已使用缓冲区大小是否大于 kmin[ifindex] 并且 kmin[ifindex] 不等于 kmax[ifindex]
        // 概率 p 表示已使用缓冲区大小位于 kmin[ifindex] 和 kmax[ifindex] 之间的情况下发送CN帧的概率
        double p = 1.0 * (m_usedEgressQSharedBytes[ifindex][qIndex] - kmin[ifindex]) /
                   (kmax[ifindex] - kmin[ifindex]) * pmax[ifindex];
        // 生成一个随机数，如果该随机数小于 p，则返回 true，表示应该发送CN帧
        if (m_uniform_random_var.GetValue(0, 1) < p) return true;
    }
    return false;
}

void SwitchMmu::SetBroadcomParams(
    // 用于设置入口端口（ingress port）的缓冲区阈值。这个阈值表示入口端口的缓冲区在不共享的情况下的阈值
    uint32_t buffer_cell_limit_sp,  // ingress sp buffer threshold p.120
    // 用于设置入口端口（ingress port）的缓冲区共享阈值。这个阈值表示入口端口的缓冲区在共享模式下的阈值
    uint32_t
        buffer_cell_limit_sp_shared,  // ingress sp buffer shared threshold p.120, nonshare -> share
    // 用于设置每个入口端口队列（ingress port queue）的最小保证（guarantee）缓冲区大小
    uint32_t pg_min_cell,             // ingress pg guarantee p.121					---1
    // 用于设置每个入口端口的最小保证（guarantee）缓冲区大小
    uint32_t port_min_cell,           // ingress port guarantee						---2
    // 用于设置每个入口端口队列（ingress port queue）的最大缓冲区大小，超过该大小时会触发流控制（PAUSE）
    uint32_t pg_shared_limit_cell,    // max buffer for an ingress pg			---3	PAUSE
    // 用于设置每个入口端口的最大缓冲区大小，超过该大小时会触发流控制（PAUSE）
    uint32_t port_max_shared_cell,    // max buffer for an ingress port		---4	PAUSE
    // 用于设置每个入口端口队列的头部保留（headroom）限制
    uint32_t pg_hdrm_limit,           // ingress pg headroom
    // 用于设置每个入口端口的最大数据包大小
    uint32_t port_max_pkt_size,       // ingress global headroom
    // 用于设置每个出口端口队列的最小保证（guarantee）缓冲区大小
    uint32_t q_min_cell,              // egress queue guaranteed buffer
    // 用于设置每个出口端口的队列阈值
    uint32_t op_uc_port_config1_cell,      // egress queue threshold
    // 用于设置每个出口端口的缓冲区阈值
    uint32_t op_uc_port_config_cell,       // egress port threshold
    // 用于设置每个出口端口的共享缓冲区阈值
    uint32_t op_buffer_shared_limit_cell,  // egress sp threshold
    // q_shared_alpha_cell: 用于设置出口队列的共享阈值（alpha）。
    // port_share_alpha_cell: 用于设置入口端口的共享阈值（alpha）。
    // pg_qcn_threshold: 用于设置每个入口端口队列的拥塞阈值
    uint32_t q_shared_alpha_cell, uint32_t port_share_alpha_cell, uint32_t pg_qcn_threshold) {
    m_buffer_cell_limit_sp = buffer_cell_limit_sp;
    m_buffer_cell_limit_sp_shared = buffer_cell_limit_sp_shared;
    m_pg_min_cell = pg_min_cell;
    m_port_min_cell = port_min_cell;
    m_pg_shared_limit_cell = pg_shared_limit_cell;
    m_port_max_shared_cell = port_max_shared_cell;
    for (int i = 0; i < pCnt; i++) m_pg_hdrm_limit[i] = pg_hdrm_limit;
    m_port_max_pkt_size = port_max_pkt_size;
    m_q_min_cell = q_min_cell;
    m_op_uc_port_config1_cell = op_uc_port_config1_cell;
    m_op_uc_port_config_cell = op_uc_port_config_cell;
    m_op_buffer_shared_limit_cell = op_buffer_shared_limit_cell;
    m_pg_shared_alpha_cell = q_shared_alpha_cell;
    m_port_shared_alpha_cell = port_share_alpha_cell;
}

uint32_t SwitchMmu::GetUsedBufferTotal() { return m_usedTotalBytes; }

void SwitchMmu::SetDynamicThreshold(bool v) {
    m_dynamicth = v;
    InitSwitch();
    return;
}

void SwitchMmu::ConfigEcn(uint32_t port, uint32_t _kmin, uint32_t _kmax, double _pmax) {
    kmin[port] = _kmin * 1000;
    kmax[port] = _kmax * 1000;
    pmax[port] = _pmax;
}

void SwitchMmu::SetPause(uint32_t port, uint32_t qIndex, uint32_t pause_time) {
    paused[port][qIndex] = true;
    Simulator::Cancel(resumeEvt[port][qIndex]);
    resumeEvt[port][qIndex] =
        Simulator::Schedule(MicroSeconds(pause_time), &SwitchMmu::SetResume, this, port, qIndex);
}
void SwitchMmu::SetResume(uint32_t port, uint32_t qIndex) {
    paused[port][qIndex] = false;
    Simulator::Cancel(resumeEvt[port][qIndex]);
}

void SwitchMmu::ConfigHdrm(uint32_t port, uint32_t size) {
    m_pg_hdrm_limit[port] = size;
    InitSwitch();
}
void SwitchMmu::ConfigNPort(uint32_t n_port) {
    m_activePortCnt = n_port;
    InitSwitch();
}
void SwitchMmu::ConfigBufferSize(uint32_t size) {
    // if size == 0, buffer size will be automatically decided
    m_staticMaxBufferBytes = size;
    InitSwitch();
}

}  // namespace ns3

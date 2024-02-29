import heapq
import math
import sys
from optparse import OptionParser


# 将带宽量纲转化为B/s
def translate_bandwidth(b):
    if b is None:
        return None
    if type(b) != str:
        return None
    if b[-1] == 'G':
        return float(b[:-1]) * 1e9
    if b[-1] == 'M':
        return float(b[:-1]) * 1e6
    if b[-1] == 'K':
        return float(b[:-1]) * 1e3
    return float(b)


# 在output_file中打印flow
def print_flow(flows, output_file):
    output_file.write("%d\n" % len(flows))  # 打印flow的数量
    heapq.heapify(flows)
    while flows:  # 按时间顺序打印flow
        flow = heapq.heappop(flows)
        output_file.write("%d %d 3 %d %.9f\n" % (flow[1], flow[2], flow[3], flow[0] * 1e-9))


# 模拟Broadcast流量生成，参数为：算法实现方式、结点编号范围、循环步长、当前维度结点个数、通信数据大小、通信开始时间
def broadcast(start_host, end_host, alpha, n_dim, comm_size, start_time):
    single_size = comm_size / n_dim  # 单次通信数据大小
    src = start_host  # 第一个源结点
    for _ in range(n_dim):  # 按循环步长遍历当前维所有源结点
        dst = src + alpha  # 目的结点
        dst %= end_host + 1
        if dst < start_host:
            dst += start_host
        while dst != src:  # 按循环步长遍历当前维的所有符合条件的目的结点，生成对应流量
            flow_new = (base_t + start_time, src, dst, single_size)
            heapq.heappush(flow_list, flow_new)
            dst += alpha
            dst %= end_host + 1
            if dst < start_host:
                dst += start_host
        src += alpha
        src %= end_host + 1


# Ring-based All-Reduce算法的实现，可分为Reduce-Scatter部分和All-Gather部分
def ring(start_host, end_host, alpha, n_dim, comm_size, start_time, end_time):
    single_size = comm_size / n_dim  # 单次通信数据大小
    t = base_t + start_time
    n_flow = n_dim - 1  # 进行Reduce-Scatter或All-Gather的次数
    gap_t = (end_time - start_time) / n_flow

    for i in range(n_flow):
        src_host = start_host  # 第一个源结点
        for j in range(n_dim):  # 按循环步长遍历当前维所有源结点，目的结点即为源结点加上循环步长
            dst_host = (src_host + alpha) % (end_host + 1)
            if dst_host < start_host:
                dst_host += start_host
            flow_new = (t, src_host, dst_host, single_size)
            heapq.heappush(flow_list, flow_new)
            src_host += alpha
        t += gap_t


# Recursive Halving Reduce-Scatter算法的实现，可做为Rabenseifner All-Reduce算法的Reduce-Scatter部分
def recursive_halving(start_host, alpha, n_dim, comm_size, start_time, end_time):
    # 计算通信步数
    # 如果n_dim为2的整数次幂，那么通信步数为log2(n_dim)
    comm_steps = 0
    while 2 ** comm_steps < n_dim:
        comm_steps += 1
    gap_t = (end_time - start_time) * 0.5 / (1 - 0.5 ** comm_steps)

    t = 0
    for step in range(comm_steps):
        dist = 2 ** (comm_steps - step - 1)  # 计算距离，第一次距离为n_host/2
        single_size = comm_size / 2 ** (step + 1)  # 第一次单个server通信大小为comm_size/2
        src = start_host
        for _ in range(n_dim):
            if (src // alpha) // dist == 0:  # 计算通信目标结点
                dst = src + dist * alpha
            else:
                dst = src - dist * alpha
            flow_new = (base_t + start_time + t, src, dst, single_size)
            heapq.heappush(flow_list, flow_new)
            src += alpha
        t += gap_t
        gap_t /= 2


# Recursive Doubling All-Gather算法的实现，可做为Rabenseifner All-Reduce算法的All-Gather部分
def recursive_doubling(start_host, alpha, n_dim, comm_size, start_time, end_time):
    comm_steps = 0  # 计算通信步数
    while 2 ** comm_steps < n_dim:
        comm_steps += 1
    gap_t = (end_time - start_time) / (2 ** comm_steps - 1)

    t = 0
    single_size = comm_size / n_dim
    for step in range(comm_steps):
        dist = 2 ** step  # 计算距离
        src = start_host
        for _ in range(n_dim):
            if (src // alpha) // dist == 0:  # 计算通信目标结点
                dst = src + dist * alpha
            else:
                dst = src - dist * alpha
            flow_new = (base_t + start_time + t, src, dst, single_size)
            heapq.heappush(flow_list, flow_new)
            src += alpha
        t += gap_t
        gap_t *= 2
        single_size *= 2


# 模拟Reduce-Scatter流量生成，参数为：算法实现方式、结点编号范围、循环步长、当前维结点个数、通信数据大小、通信开始时间、流量列表
def reduce_scatter(implementation, start_host, end_host, alpha, n_dim, comm_size, start_time, end_time):
    if implementation == "direct":  # 朴素算法
        broadcast(start_host, end_host, alpha, n_dim, comm_size, start_time)
    elif implementation == "ring":  # Ring-based算法
        ring(start_host, end_host, alpha, n_dim, comm_size, start_time, end_time)
    elif implementation == "rabenseifner":  # Rabenseifner算法的Reduce_Scatter部分
        recursive_halving(start_host, alpha, n_dim, comm_size, start_time, end_time)


# 模拟All_Gather流量生成，参数为：算法实现方式、结点编号范围、循环步长、当前维结点个数、通信数据大小、通信开始时间、流量列表
def all_gather(implementation, start_host, end_host, alpha, n_dim, comm_size, start_time, end_time):
    if implementation == "direct":  # 朴素算法
        broadcast(start_host, end_host, alpha, n_dim, comm_size, start_time)
    elif implementation == "ring":  # Ring-based算法
        ring(start_host, end_host, alpha, n_dim, comm_size, start_time, end_time)
    elif implementation == "rabenseifner":  # Rabenseifner算法的All-Gather部分
        recursive_doubling(start_host, alpha, n_dim, comm_size, start_time, end_time)


# Recursive Doubling All-Reduce算法的实现，不可拆分为Reduce-Scatter和All_Gather，暂时只支持1D All-Reduce
def butterfly(start_host, alpha, n_dim, comm_size, start_time, end_time):
    comm_steps = 0  # 计算通信步数
    while 2 ** comm_steps < n_dim:
        comm_steps += 1
    gap_t = (end_time - start_time) / comm_steps

    t = 0
    for step in range(comm_steps):
        dist = 2 ** step  # 计算距离
        src = start_host
        for _ in range(n_dim):
            if (src // alpha) // dist == 0:  # 计算通信目标结点
                dst = src + dist * alpha
            else:
                dst = src - dist * alpha
            flow_new = (base_t + start_time + t, src, dst, comm_size)
            print(flow_new)
            heapq.heappush(flow_list, flow_new)
            src += alpha
        t += gap_t


# All-to-all Bruck算法的实现
def bruck(start_host, end_host, alpha, n_dim, comm_size, start_time, end_time):
    n_step = int(math.log2(n_dim))
    gap_t = (end_time - start_time) / n_step

    t = 0
    for i in range(n_step):
        src = start_host
        for _ in range(n_dim):
            dst = src + (2 ** i) * alpha
            dst %= end_host + 1
            flow_new = (base_t + start_time + t, src, dst, comm_size / 2)  # 仅在结点数为2的正整数幂时成立
            heapq.heappush(flow_list, flow_new)  # 按流量大小进行堆排序
            src += alpha
        t += gap_t


# All-to-all Pairwise Exchange算法的实现
def pairwise_exchange(n_dim, comm_size, start_time, end_time):
    t = base_t + start_time
    n_step = int(math.log2(n_dim))
    gap_t = (end_time - start_time) / n_step
    for step in range(n_step):
        k = 2 ** step
        for src in range(n_dim):
            dst = (src ^ k) % n_dim
            flow_new = (t, src, dst, comm_size / 2)  # 仅在结点数为2的正整数幂时成立
            heapq.heappush(flow_list, flow_new)
        t += gap_t


# 1D 和 2D All-Reduce的实现
def all_reduce():
    if dimension == 1:
        if impl == "butterfly":
            comm_steps = 0  # 计算通信步数
            while 2 ** comm_steps < n_host:
                comm_steps += 1
            start_time = 0
            for i in range(layer_num):
                comm_size = size_per_layer[i]
                total_size = comm_size * n_host
                send_size = total_size * comm_steps
                single_time = 1 / (bandwidth * load / 8. / send_size) * 1000000000
                butterfly(0, 1, n_host, total_size, start_time, start_time + single_time)
                start_time += single_time
        else:
            comm_steps = 0  # 计算通信步数
            while 2 ** comm_steps < n_host:
                comm_steps += 1
            start_time = 0
            for i in range(layer_num):
                comm_size = size_per_layer[i]
                total_size = comm_size * n_host
                if impl == "rabenseifner":
                    send_size = 0
                    for j in range(comm_steps):
                        send_size += total_size / (2 ** (j + 1))
                else:
                    send_size = comm_size * (n_host - 1)
                single_time = 1 / (bandwidth * load / 8. / send_size) * 1000000000
                if start_time + single_time * 2 > time:
                    break
                # 先进行Reduce-Scatter，算法实现方式为impl，结点编号范围为0到n_host-1，循环步长为1
                reduce_scatter(impl,
                               0,
                               n_host - 1,
                               1,
                               n_host,
                               total_size,
                               start_time,
                               start_time + single_time
                               )
                # 在进行All_Gather，算法实现方式为impl，结点编号范围为0到n_host-1，循环步长为1，起始时间为0+interval
                all_gather(impl,
                           0,
                           n_host - 1,
                           1,
                           n_host,
                           total_size,
                           start_time + single_time,
                           start_time + single_time * 2
                           )
                start_time += single_time * 2
    elif dimension == 2:
        impl_list = impl.split('_')
        impl_x = impl_list[0]
        impl_y = impl_list[1]
        dim_list = dims.split('_')  # 解析各维度的结点数量
        dim_list = [int(dim_list[i]) for i in range(len(dim_list))]
        dim_x = dim_list[0]  # x轴结点数量
        dim_y = dim_list[1]  # y轴结点数量

        start_time = 0
        for j in range(layer_num):
            comm_size = size_per_layer[j]
            total_size = comm_size * n_host
            send_size = 0
            if impl_x == "rabenseifner":
                comm_steps = 0  # 计算通信步数
                while 2 ** comm_steps < dim_x:
                    comm_steps += 1
                send_size = 0
                for i in range(comm_steps):
                    send_size += total_size / (2 ** (i + 1)) * 2  # 单次rabenseifner单个server发出的flow大小
            else:
                send_size += total_size / dim_x * (dim_x - 1) * 2  # 单次direct单个server发出的flow大小
            if impl_y == "rabenseifner":
                comm_steps = 0  # 计算通信步数
                while 2 ** comm_steps < dim_y:
                    comm_steps += 1
                for i in range(comm_steps):
                    send_size += (total_size / dim_x) / (2 ** (i + 1)) * 2  # 单次rabenseifner单个server发出的flow大小
            else:
                send_size += (total_size / dim_x) / dim_y * (dim_y - 1)
            single_time = 1 / (bandwidth * load / 8. / send_size) * 1000000000
            if start_time + single_time > time:
                break
            for i in range(0, dim_y * dim_x, dim_x):  # 先进行第一维度的Reduce-Scatter
                reduce_scatter(impl_x,
                               i,
                               i + dim_x - 1,
                               1,
                               dim_x,
                               total_size,
                               start_time,
                               start_time + single_time / 2 * (total_size / (total_size + total_size / dim_x))
                               )
            for i in range(dim_x):  # 再进行第二维度的Reduce-Scatter
                reduce_scatter(impl_y,
                               i,
                               n_host - 1,
                               dim_x,
                               dim_y,
                               total_size / dim_x,
                               start_time + single_time / 2 * (total_size / (total_size + total_size / dim_x)),
                               start_time + single_time / 2
                               )
            for i in range(dim_x):  # 再进行第二维度的All_Gather
                all_gather(impl_y,
                           i,
                           n_host - 1,
                           dim_x,
                           dim_y,
                           total_size / dim_x,
                           start_time + single_time / 2,
                           start_time + single_time / 2 + single_time / 2 * ((total_size / dim_x) / (total_size + total_size / dim_x))
                           )
            for i in range(0, dim_y * dim_x, dim_x):  # 最后进行第一维度的All_Gather
                all_gather(impl_x,
                           i,
                           i + dim_x - 1,
                           1,
                           dim_x,
                           total_size,
                           start_time + single_time / 2 + single_time / 2 * ((total_size / dim_x) / (total_size + total_size / dim_x)),
                           start_time + single_time
                           )
            start_time += single_time


# All-to-All算法的实现
def all_to_all(implementation, start_host, end_host, alpha, n_dim, start_time):
    if implementation == "direct":  # 朴素算法
        for i in range(layer_num):
            comm_size = size_per_layer[i]
            total_size = comm_size * n_host
            send_size = comm_size * (n_host - 1)
            single_time = 1 / (bandwidth * load / 8. / send_size) * 1000000000
            if start_time + single_time > time:
                break
            broadcast(start_host, end_host, alpha, n_dim, total_size, start_time)
            start_time += single_time
    else:
        comm_steps = 0  # 计算通信步数
        while 2 ** comm_steps < n_host:
            comm_steps += 1
        for i in range(layer_num):
            comm_size = size_per_layer[i]
            total_size = comm_size * n_host
            send_size = total_size / 2
            single_time = 1 / (bandwidth * load / 8. / send_size) * 1000000000
            if start_time + single_time > time:
                break
            if implementation == "bruck":  # Bruck算法
                bruck(start_host, end_host, alpha, n_dim, total_size, start_time, start_time + single_time)
            elif implementation == "pairwiseExchange":
                pairwise_exchange(n_dim, total_size, start_time, start_time + single_time)
            start_time += single_time


if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-n", "--n_host", dest="n_host", help="number of hosts")
    parser.add_option("-l", "--load", dest="load",
                      help="the percentage of the traffic load to the network capacity, by default 0.3", default="0.3")
    parser.add_option("-b", "--bandwidth", dest="bandwidth", help="the bandwidth of host link (G/M/K), by default 10G",
                      default="10G")
    parser.add_option("-t", "--time", dest="time", help="the total run time (s), by default 10", default="10")
    parser.add_option("-a", "--algorithm", dest="algorithm", help="collective communication algorithm",
                      default="all-reduce")
    parser.add_option("-i", "--impl", dest="impl", help="the implementation of the algorithm", default="direct")
    parser.add_option("-p", "--physical_dims", dest="physical_dims", help="the physical dimensions")
    parser.add_option("-o", "--output", dest="output", help="the output file", default="tmp_traffic.txt")
    options, args = parser.parse_args()

    if not options.n_host:
        print("please use -n to enter number of hosts")
        sys.exit(0)
    if not options.physical_dims:
        print("please use -p to enter the physical dimensions")
    n_host = int(options.n_host)
    load = float(options.load)
    bandwidth = translate_bandwidth(options.bandwidth)
    time = float(options.time) * 1e9  # translates to ns
    algorithm = options.algorithm
    impl = options.impl
    dims = options.physical_dims
    dimension = len(dims.split('_'))
    output = options.output

    base_t = 2000000000
    # 512KB 1MB 2MB 4MB 8MB 16MB 32MB 64MB 128MB 256MB 512MB 1GB
    size_per_layer = [524288, 1048576, 2097152, 4194304, 8388608,
                      16777216, 33554432, 67108864,          2359296, 1048576, 2359296, 1048576,
                      8388608, 2097152, 9437184, 4194304, 4194304, 9437184, 4194304]
    layer_num = len(size_per_layer)

    o_file = open(output, "w")

    flow_list = []  # 流量列表
    heapq.heapify(flow_list)
    if algorithm == "all-reduce":  # 选择流量模式为All-Reduce
        all_reduce()
    else:
        all_to_all(impl, 0, n_host - 1, 1, n_host, 0)
    print_flow(flow_list, o_file)

    o_file.close()

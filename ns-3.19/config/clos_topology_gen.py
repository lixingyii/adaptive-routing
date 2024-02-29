n_spine = 16
n_pod = 16
link_rate = 400  # Gbps
link_latency = 1000  # ns
over_subscript = 2

n_agg_per_pod = 2
n_tor_per_pod = 2
n_server_per_tor = n_tor_per_pod * over_subscript
n_server_per_pod = n_server_per_tor * 2

print("Number of spine: {}".format(n_spine))
print("Number of pods: {}".format(n_pod))
print("Number of Agg per pod: {}, total: {}".format(n_agg_per_pod, n_agg_per_pod * n_pod))
print("Number of ToR per pod: {}, total: {}".format(n_tor_per_pod, n_tor_per_pod * n_pod))
print("Number of servers per ToR: {} (over-subscript:{})".format(n_server_per_tor, over_subscript))
print("Number of servers per pod: {}, total: {}".format(n_server_per_pod, n_server_per_pod * n_pod))

n_server_total = n_server_per_pod * n_pod
n_tor_total = n_tor_per_pod * n_pod
n_agg_total = n_tor_per_pod * n_pod
n_spine_total = n_spine
n_node_total = n_server_total + n_tor_total + n_agg_total + n_spine_total
n_switch_total = n_tor_total + n_agg_total + n_spine_total
n_link = n_spine_total * n_agg_total + n_pod * n_agg_per_pod * n_tor_per_pod + n_tor_total * n_server_per_tor

i_server = 0
i_tor = n_server_total
i_agg = n_server_total + n_tor_total
i_spine = n_server_total + n_tor_total + n_agg_total

i_link = 0
filename = "leaf_spine_{}_{}G_OS{}.txt".format(n_server_total, link_rate, over_subscript)
with open(filename, "w") as f:
    f.write("{} {} {}\n".format(n_node_total, n_switch_total, n_link))

    for i in range(n_switch_total):
        if i == n_switch_total - 1:
            f.write("{}\n".format(i + n_server_total))
        else:
            f.write("{} ".format(i + n_server_total))

    for p in range(n_tor_total):
        for i in range(n_server_per_tor):
            id_server = p * n_server_per_tor + i
            id_tor = i_tor + p
            f.write("{} {} {}Gbps {}ns 0\n".format(id_server, id_tor, link_rate, link_latency))
            i_link += 1

    for i in range(n_pod):
        for j in range(n_tor_per_pod):
            for k in range(n_agg_per_pod):
                id_tor = i_tor + i * n_tor_per_pod + j
                id_agg = i_agg + i * n_tor_per_pod + k
                f.write("{} {} {}Gbps {}ns 0\n".format(id_tor, id_agg, link_rate, link_latency))
                i_link += 1

    for i in range(n_agg_total):
        for j in range(n_spine_total):
            id_agg = i_agg + i
            id_spine = i_spine + j
            f.write("{} {} {}Gbps {}ns 0\n".format(id_agg, id_spine, link_rate, link_latency))
            i_link += 1


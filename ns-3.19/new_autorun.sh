#!/bin/bash

cecho(){  # source: https://stackoverflow.com/a/53463162/2886168
    RED="\033[0;31m"
    GREEN="\033[0;32m"
    YELLOW="\033[0;33m"
    # ... ADD MORE COLORS
    NC="\033[0m" # No Color

    printf "${!1}${2} ${NC}\n"
}

cecho "GREEN" "Running RDMA Network Load Balancing Simulations (leaf-spine topology)"

TOPOLOGY="leaf_spine_128_400G_OS2" # topology
NETLOAD="75" # network load 75%
RUNTIME="0.5" # 0.5 second (traffic generation)
ALGORITHM="all-reduce"
IMPLEMENTATION="ring_ring"
PHYSICAL_DIMS="128"

cecho "YELLOW" "\n----------------------------------"
cecho "YELLOW" "TOPOLOGY: ${TOPOLOGY}" 
cecho "YELLOW" "NETWORK LOAD: ${NETLOAD}" 
cecho "YELLOW" "TIME: ${RUNTIME}" 
cecho "YELLOW" "ALGORITHM: ${ALGORITHM}"
cecho "YELLOW" "IMPLEMENTATION: ${IMPLEMENTATION}"
cecho "YELLOW" "----------------------------------\n"

# Lossless RDMA
cecho "GREEN" "Run Lossless RDMA experiments..."
# python3.8 run.py --cc dcqcn --lb fecmp --pfc 1 --irn 0 --simul_time ${RUNTIME} --netload ${NETLOAD} --topo ${TOPOLOGY} --algorithm ${ALGORITHM} --implementation ${IMPLEMENTATION} --physical_dims ${PHYSICAL_DIMS} 2>&1 > /dev/null & 
# sleep 5
# python3.8 run.py --cc dcqcn --lb conga --pfc 1 --irn 0 --simul_time ${RUNTIME} --netload ${NETLOAD} --topo ${TOPOLOGY} --algorithm ${ALGORITHM} --implementation ${IMPLEMENTATION} --physical_dims ${PHYSICAL_DIMS} 2>&1 > /dev/null &
# sleep 5
# python3.8 run.py --cc dcqcn --lb letflow --pfc 1 --irn 0 --simul_time ${RUNTIME} --netload ${NETLOAD} --topo ${TOPOLOGY} --algorithm ${ALGORITHM} --implementation ${IMPLEMENTATION} --physical_dims ${PHYSICAL_DIMS} 2>&1 > /dev/null &
# sleep 5
python3.8 run.py --cc dcqcn --lb adaptive --pfc 1 --irn 0 --simul_time ${RUNTIME} --netload ${NETLOAD} --topo ${TOPOLOGY} --algorithm ${ALGORITHM} --implementation ${IMPLEMENTATION} --physical_dims ${PHYSICAL_DIMS} 2>&1 > /dev/null &
sleep 5

# IRN RDMA
# cecho "GREEN" "Run IRN RDMA experiments..."
# python3 run.py --cc dcqcn --lb fecmp --pfc 0 --irn 1 --simul_time ${RUNTIME} --netload ${NETLOAD} --topo ${TOPOLOGY} --algorithm ${ALGORITHM} --implementation ${IMPLEMENTATION} --physical_dims ${PHYSICAL_DIMS} 2>&1 > /dev/null &
# sleep 5
# python3 run.py --cc dcqcn --lb conga --pfc 0 --irn 1 --simul_time ${RUNTIME} --netload ${NETLOAD} --topo ${TOPOLOGY} --algorithm ${ALGORITHM} --implementation ${IMPLEMENTATION} --physical_dims ${PHYSICAL_DIMS} 2>&1 > /dev/null &
# sleep 5
# python3 run.py --cc dcqcn --lb letflow --pfc 0 --irn 1 --simul_time ${RUNTIME} --netload ${NETLOAD} --topo ${TOPOLOGY} --algorithm ${ALGORITHM} --implementation ${IMPLEMENTATION} --physical_dims ${PHYSICAL_DIMS} 2>&1 > /dev/null &
# sleep 5
# python3 run.py --cc dcqcn --lb conweave --pfc 0 --irn 1 --simul_time ${RUNTIME} --netload ${NETLOAD} --topo ${TOPOLOGY} --algorithm ${ALGORITHM} --implementation ${IMPLEMENTATION} --physical_dims ${PHYSICAL_DIMS} 2>&1 > /dev/null &
# sleep 5

cecho "GREEN" "Runing all in parallel. Check the processors running on background!"
#!/usr/bin/python

import ast

def read_node_file(path): 
    node_str = ''
    with open(path, 'r') as nf:
        node_str = nf.read()
    node_str = node_str.replace('\r\n', '')
    node_str = node_str.replace('[', '')
    node_str = node_str.replace(']', '')
    nodes = map(int, node_str.rstrip().split('.')[0:-1])
    return nodes

def read_partitions_file(path):
    flow_dict = {}
    with open(path, 'r') as pf:
        for line in pf:
            s1 = line.split(':')
            index_str = s1[0]
            val_str = s1[1]
            flow_num = int(index_str[2:-1].split(',')[0])
            flow_dict.setdefault(flow_num, []).append(float(val_str))
    return flow_dict

def parse_flow_defs(path, seed_no):
    # flow_dir = path + './seed_%s/' % seed_no
    flow_dir = path
    dests = read_node_file(flow_dir + ('./Destinations_seed_%s.txt') % seed_no)
    origins = read_node_file(flow_dir + ('./Origins_seed_%s.txt') % seed_no)
    parts = read_partitions_file(flow_dir + ('./X_matrix_seed_%s.txt') % seed_no)
    od_pairs = zip([O_n + 1 for O_n in origins], [D_n + 1 for D_n in dests])
    seen = []
    for elem in od_pairs:
        if elem in seen:
            print elem, 'is a duplicate.'
        seen.append(elem)
    flows = {}
    for ind, p in enumerate(od_pairs):
        flows[p] = parts[ind]
    return flows

def read_route_file(path):
    lst = []
    with open(path, 'r') as rf:
        lst = ast.literal_eval(rf.read())
    return lst

def parse_routes(path, seed_no):
    routes_path = path + './Paths_seed_%s.txt' % seed_no 
    routes = read_route_file(routes_path)
    return routes

if __name__ == '__main__':
    fds = parse_flow_defs('/home/alex/programming/research_18/multipath/results/seed_5678/probabilistic_mean_1_variance_1/', '5678')
    print len(fds)

    
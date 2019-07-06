
import ast
import abc

class FileParser(metaclass=abc.ABCMeta):

    def __init__(self):
        pass

    @abc.abstractmethod
    def get_routes(self):
        pass

    @abc.abstractmethod
    def get_flow_defs(self):
        pass

class MPTestFileParser(FileParser):
    def __init__(self, route_dir, seed_no):
        FileParser.__init__(self)
        self._route_dir = route_dir
        self._seed_no = seed_no
    
    def _read_route_file(self, path):
        lst = []
        with open(path, 'r') as rf:
            lst = ast.literal_eval(rf.read())
        return lst

    def get_routes(self):
        routes_path = self._route_dir + './Paths_seed_%s.txt' % self._seed_no 
        routes = self._read_route_file(routes_path)
        return routes

    def _read_node_file(self, path): 
        node_str = ''
        with open(path, 'r') as nf:
            node_str = nf.read()
        node_str = node_str.replace('\r\n', '')
        node_str = node_str.replace('[', '')
        node_str = node_str.replace(']', '')
        nodes = map(int, node_str.rstrip().split('.')[0:-1])
        return nodes

    def _read_partitions_file(self, path):
        flow_dict = {}
        with open(path, 'r') as pf:
            for line in pf:
                s1 = line.split(':')
                index_str = s1[0]
                val_str = s1[1]
                flow_num = int(index_str[2:-1].split(',')[0])
                flow_dict.setdefault(flow_num, []).append(float(val_str))
        return flow_dict

    def get_flow_defs(self):
        # flow_dir = path + './seed_%s/' % seed_no
        flow_dir = self._route_dir
        dests = self._read_node_file(flow_dir + ('./Destinations_seed_%s.txt') % self._seed_no)
        origins = self._read_node_file(flow_dir + ('./Origins_seed_%s.txt') % self._seed_no)
        parts = self._read_partitions_file(flow_dir + ('./X_matrix_seed_%s.txt') % self._seed_no)
        od_pairs = zip([O_n + 1 for O_n in origins], [D_n + 1 for D_n in dests])
        seen = []
        for elem in od_pairs:
            if elem in seen:
                print(elem, 'is a duplicate.')
            seen.append(elem)
        flows = {}
        for ind, p in enumerate(od_pairs):
            flows[p] = parts[ind]
        return flows


    
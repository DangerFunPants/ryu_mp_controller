
def show_dpid(dpid):
        str_rep = ''
        for _ in range(7):
            str_rep = '%d:' % (dpid & 0xff) + str_rep
            dpid = dpid >> 8
        return str_rep[:-1]
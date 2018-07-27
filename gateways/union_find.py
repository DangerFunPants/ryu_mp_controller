#!/usr/bin/env python

class Node:
    def __init__(self, id):
        self.id = id
        self.parent = self

    def __repr__(self):
        return '(%d, %d)' % (self.id, self.parent.id)

def make_set(x):
    x_node = Node(x)
    return x_node

def find(n):
    if n.parent != n:
        n.parent = find(n.parent)
    return n.parent

def union(n1, n2):
    n1_root = find(n1)
    n2_root = find(n2)

    if n1_root == n2_root:
        return
    
    n1_root.parent = n2_root

def main():
    nodes = [make_set(i) for i in range(1, 10)]
    map(lambda n : union(n, nodes[0]), nodes)
    print nodes

    for n in nodes:
        print find(n)

if __name__ == '__main__':
    main()

    

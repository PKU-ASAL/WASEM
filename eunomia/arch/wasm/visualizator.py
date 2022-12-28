from eunomia.arch.wasm.configuration import Configuration
from graphviz import Digraph

def instructions_details(bb,Graph,format='hex'):
    instructions = Graph._bb_to_instructions[bb]
    func_to_bbs = Graph._func_to_bbs
    funcname = ''
    found = 0
    for func in func_to_bbs:
        if found:
            break
        for basicblock in func_to_bbs[func]:
            if bb == basicblock:
                found = 1
                funcname = func
                break

    out = funcname + '\n' + bb + '\n'
    line = ''
    for i in instructions:
        line = '%x: ' % i.offset
        if i.operand is not None and not i.xref:
            line += '%s' % str(i)
        elif isinstance(i.xref, list) and i.xref:
            line += '%s %s' % (i.name, i.xref)
        elif isinstance(i.xref, int) and i.xref:
            line += '%s %x' % (i.name, i.xref)
        elif i.operand_interpretation:
            line += i.operand_interpretation
        else:
            line += i.name + ' '

        out += line + '\n'
    return out

def visualize(Graph, filename="wasm_ICFG.gv"):
    entry_func = Configuration.get_entry()
    entry_func_index_name = Graph.wasmVM.get_signature(entry_func)[0]
    entry_bb = Graph.func_to_bbs[entry_func_index_name][0]
    assert entry_bb.endswith('_0'), f"entry_bb ({entry_bb}) not ends with 0"

    g = Digraph(filename, filename=filename)
    g.attr(rankdir="TB")

    # construct a set consisting of edges (nodeA, nodeB, edge_type)
    visited = set()
    edges_set = set()
    stack = list()
    stack.append(entry_bb)
    nodes = []
    nodes.append(entry_bb)
    while stack:
        bb = stack.pop()
        visited.add(bb)
        if bb in Graph.bbs_graph:
            for edge_type, succ_bb in Graph.bbs_graph[bb].items():
                if succ_bb not in visited:
                    edges_set.add((bb, succ_bb, edge_type))
                    stack.append(succ_bb)
                    nodes.append(succ_bb)
                elif (bb, succ_bb, edge_type) not in edges_set:
                    edges_set.add((bb, succ_bb, edge_type))

    with g.subgraph(name='global') as c:
        # construct the graph
        for node in nodes:
            c.node(node, label = instructions_details(node,Graph))

        for edge in edges_set:
            node_from, node_to, _ = edge
            c.edge(node_from, node_to, _)

    print("Rendering...")
    g.render(filename, view=True)

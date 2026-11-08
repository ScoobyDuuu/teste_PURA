"""Algoritmos de grafo (Dijkstra) sem dependências externas."""
from __future__ import annotations

import heapq
from typing import Callable, Dict, Optional

from .model import Link, Network, Path, ekey

Weight = Callable[[Link], float]


def dijkstra(net: Network, src: str, dst: str, weight: Weight,
             node_ok: Optional[Callable[[str], bool]] = None,
             edge_ok: Optional[Callable[[Link], bool]] = None) -> Optional[Path]:
    dist: Dict[str, float] = {src: 0.0}
    prev: Dict[str, str] = {}
    pq = [(0.0, src)]
    seen = set()
    while pq:
        d, u = heapq.heappop(pq)
        if u in seen:
            continue
        seen.add(u)
        if u == dst:
            break
        for v in net.neighbors(u):
            if node_ok and not node_ok(v):
                continue
            link = net.links[ekey(u, v)]
            if edge_ok and not edge_ok(link):
                continue
            nd = d + weight(link)
            if nd < dist.get(v, float("inf")):
                dist[v] = nd
                prev[v] = u
                heapq.heappush(pq, (nd, v))
    if dst not in dist:
        return None
    path = [dst]
    while path[-1] != src:
        path.append(prev[path[-1]])
    return tuple(reversed(path))


def distances_from(net: Network, src: str, weight: Weight,
                   node_ok: Optional[Callable[[str], bool]] = None) -> Dict[str, float]:
    """Distâncias mínimas de src a todos os nós (grafo não direcionado)."""
    dist: Dict[str, float] = {src: 0.0}
    pq = [(0.0, src)]
    seen = set()
    while pq:
        d, u = heapq.heappop(pq)
        if u in seen:
            continue
        seen.add(u)
        for v in net.neighbors(u):
            if node_ok and not node_ok(v):
                continue
            nd = d + weight(net.links[ekey(u, v)])
            if nd < dist.get(v, float("inf")):
                dist[v] = nd
                heapq.heappush(pq, (nd, v))
    return dist

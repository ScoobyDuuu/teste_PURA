from .aco import ACORouter
from .base import Router
from .baselines import DijkstraResidualRouter, DijkstraRouter, StaticRouter
from .memetic import MemeticRouter

ROUTERS = ("static", "dijkstra", "dijkstra_residual", "aco", "memetic")


def make_router(name: str, seed: int = 0) -> Router:
    """Fábrica (Strategy): troca de otimizador por nome, sem alterar o simulador."""
    if name == "static":
        return StaticRouter()
    if name == "dijkstra":
        return DijkstraRouter()
    if name == "dijkstra_residual":
        return DijkstraResidualRouter()
    if name == "aco":
        return ACORouter(seed=seed)
    if name == "memetic":
        return MemeticRouter(seed=seed)
    raise ValueError(f"roteador desconhecido: {name}")


__all__ = ["Router", "ROUTERS", "make_router", "StaticRouter", "DijkstraRouter",
           "DijkstraResidualRouter", "ACORouter", "MemeticRouter"]

"""Segurança da telemetria: HMAC-SHA256 + proteção contra replay.

Garante integridade e autenticidade das mensagens entre nós ESP32 e gateway.
Confidencialidade vem do TLS (terminado na nuvem ou no proxy); ver ADR-0004 e ADR-0007.

Correções de vulnerabilidades (ver docs/VULNERABILIDADES.md):
  VULN-001  ReplayGuard aceitava replay de mensagens de um boot antigo.
  VULN-002  O gateway subia com um segredo padrão público se PURA_SECRET faltasse.
  VULN-006  O estado anti-replay fica em RAM: após reinício/hibernação do gateway, tudo capturado era aceito.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import os
import threading
from collections import OrderedDict
from typing import Dict

MIN_SECRET_LEN = 16
MAX_BOOTS_PER_NODE = 256
MAX_REPLAY_NODES = 1024
DEFAULT_TS_WINDOW_S = 120


class WeakSecretError(RuntimeError):
    pass


class ReplayCapacityError(RuntimeError):
    """O limite seguro de nós rastreados foi atingido; novas identidades são recusadas."""



def load_secret() -> bytes:
    """Lê PURA_SECRET. Sem segredo forte o gateway se recusa a subir (VULN-002).

    Para laboratório, PURA_ALLOW_DEV_SECRET=1 permite um segredo de desenvolvimento, com aviso.
    """
    env = os.environ.get("PURA_SECRET", "")
    if len(env) >= MIN_SECRET_LEN:
        return env.encode()
    if os.environ.get("PURA_ALLOW_DEV_SECRET") == "1":
        return b"segredo-de-desenvolvimento-nao-usar-em-producao"
    raise WeakSecretError(
        f"Defina PURA_SECRET com pelo menos {MIN_SECRET_LEN} caracteres "
        "(ou PURA_ALLOW_DEV_SECRET=1 apenas em laboratório)."
    )


def sign(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def verify(secret: bytes, body: bytes, signature: str) -> bool:
    if not signature:
        return False
    return hmac.compare_digest(sign(secret, body), signature.strip().lower())


class ReplayGuard:
    """Rejeita qualquer (boot, seq) já visto ou anterior ao último seq daquele boot.

    Guarda o maior seq dos últimos boots registrados (até MAX_BOOTS_PER_NODE por nó),
    então replay de boots retidos é rejeitado (corrige VULN-001). Um boot novo é aceito,
    pois só o dono do segredo consegue assinar uma mensagem inédita.
    Risco residual: mensagens retidas pelo atacante e entregues depois (sem relógio no nó).

    A memória é limitada a MAX_REPLAY_NODES identidades e MAX_BOOTS_PER_NODE boots por nó.
    Ao atingir o limite de identidades, novos nós são recusados (fail-closed); o estado de
    segurança de nós já conhecidos nunca é removido automaticamente para abrir espaço.
    """

    def __init__(self, max_nodes: int = MAX_REPLAY_NODES) -> None:
        if max_nodes < 1:
            raise ValueError("max_nodes deve ser >= 1")
        self.max_nodes = max_nodes
        self._last: Dict[str, "OrderedDict[int, int]"] = OrderedDict()
        self._lock = threading.Lock()

    def accept(self, node: str, boot: int, seq: int) -> bool:
        with self._lock:
            boots = self._last.get(node)
            if boots is None:
                if len(self._last) >= self.max_nodes:
                    raise ReplayCapacityError(
                        f"limite de {self.max_nodes} nós rastreados atingido"
                    )
                boots = OrderedDict()
                self._last[node] = boots
            else:
                self._last.move_to_end(node)
            if boot in boots and seq <= boots[boot]:
                return False
            boots[boot] = seq
            boots.move_to_end(boot)
            while len(boots) > MAX_BOOTS_PER_NODE:
                boots.popitem(last=False)
            return True


def timestamp_ok(ts, now: float, required: bool, window_s: float = DEFAULT_TS_WINDOW_S) -> bool:
    """Valida o carimbo de tempo `ts` (epoch, em segundos) que o nó inclui no corpo ASSINADO (VULN-006).

    Com a janela, uma mensagem capturada só pode ser reenviada por `window_s` segundos, mesmo que o
    ReplayGuard (memória) tenha sido zerado por reinício. Se `required` é falso, mensagens sem `ts`
    (firmware em modo HTTP de laboratório, sem NTP) continuam aceitas; se `ts` existe, é sempre validado.
    """
    if ts is None:
        return not required
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return False
    try:
        stamp = float(ts)
        current = float(now)
        window = float(window_s)
    except (TypeError, ValueError, OverflowError):
        return False
    if not all(math.isfinite(value) for value in (stamp, current, window)) or window <= 0:
        return False
    return abs(current - stamp) <= window

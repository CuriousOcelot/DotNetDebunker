from dataclasses import dataclass


@dataclass
class LocalVarSigInfo:
    token: int
    sig: bytearray
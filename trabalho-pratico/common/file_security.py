"""
Apoio a permissões restritas para dados locais sensíveis.

As permissões são aplicadas em regime best effort, respeitando as
limitações do sistema operativo em uso.
"""

import os
from pathlib import Path


def secure_mkdir(path: Path, *, mode: int = 0o700) -> None:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    restrict_permissions(target, mode)


def restrict_permissions(path: Path, mode: int) -> None:
    if os.name == "nt":
        return
    try:
        os.chmod(path, mode)
    except OSError:
        pass

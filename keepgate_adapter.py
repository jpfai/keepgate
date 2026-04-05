"""
keepgate_adapter.py — Adaptateur minimal KeepGate pour IGNIS.

Usage dans ignis_exec_runner.py :
    from keepgate_adapter import check_output, redact_if_needed

    # Avant toute exécution de sortie :
    result = check_output(action_output)
    if result.blocked:
        log.warning(f"Sortie bloquée: {result.reason}")
        # Option 1 : blocage strict
        raise ExecutionBlocked(result.reason)
        # Option 2 : redaction explicite (si chemin autorisé)
        # cleaned = redact_if_needed(action_output)

Ce module encapsule l'appel CLI KeepGate.
Le contrat canonique reste CONTRACT_V1.md.
"""

import json
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Chemin vers le binaire keepgate — ajuster selon installation
# Possibilités :
#   - Relatif au projet IGNIS
#   - Absolu (ex: /usr/local/bin/keepgate)
#   - Dans PATH (alors juste "keepgate")
KEEKEEPATE_BIN = None  # Auto-détection


def _find_binary() -> Path:
    """Trouve le binaire keepgate."""
    import shutil
    
    # 1. Chercher dans PATH
    found = shutil.which("keepgate")
    if found:
        return Path(found)
    
    # 2. Chercher relativement au module
    module_dir = Path(__file__).parent
    candidates = [
        module_dir / "keepgate" / "target" / "release" / "keepgate",   # dev
        module_dir.parent / "keepgate" / "target" / "release" / "keepgate",
        Path.home() / ".cargo" / "bin" / "keepgate",                    # cargo install
        Path("C:/Users/33617/OpenAI-Agent/keepgate/target/release/keepgate.exe"),  # Windows
    ]
    for c in candidates:
        if c.exists():
            return c
    
    raise FileNotFoundError(
        "Binaire keepgate introuvable. "
        "Compiler avec 'cargo build --release' dans le repo keepgate, "
        "ou ajouter au PATH."
    )


# ---------------------------------------------------------------------------
# Structures de données
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    """Résultat d'un check KeepGate."""
    allowed: bool
    blocked: bool
    reason: Optional[str]
    sensitivity: Optional[str]
    raw: dict
    
    @classmethod
    def ok(cls, sensitivity: str, raw: dict) -> "CheckResult":
        return cls(allowed=True, blocked=False, reason=None, sensitivity=sensitivity, raw=raw)
    
    @classmethod
    def denied(cls, reason: str, sensitivity: str, raw: dict) -> "CheckResult":
        return cls(allowed=False, blocked=True, reason=reason, sensitivity=sensitivity, raw=raw)


@dataclass
class DetectResult:
    """Résultat d'un detect KeepGate."""
    secrets_found: int
    items: list
    raw: dict


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

_binary: Optional[Path] = None


def _get_binary() -> Path:
    global _binary
    if _binary is None:
        if KEEKEEPATE_BIN is not None:
            _binary = Path(KEEKEEPATE_BIN)
        else:
            _binary = _find_binary()
    return _binary


def _run(command: str, data: str, timeout: int = 10) -> tuple[int, dict]:
    """
    Exécute une commande KeepGate CLI.
    
    Returns:
        (exit_code, json_result)
        
    Raises:
        TimeoutError: si timeout dépassé
        RuntimeError: si erreur système (exit 2, 3, 99)
    """
    proc = subprocess.run(
        [str(_get_binary()), command],
        input=data.encode("utf-8"),
        capture_output=True,
        timeout=timeout,
    )
    
    stdout = proc.stdout.decode("utf-8", errors="replace").strip()
    
    if proc.returncode == 2:
        raise RuntimeError(f"KeepGate: erreur d'entrée — {proc.stderr.decode().strip()}")
    if proc.returncode == 3:
        raise TimeoutError("KeepGate: timeout (>10s)")
    if proc.returncode == 99:
        raise RuntimeError(f"KeepGate: erreur interne — {proc.stderr.decode().strip()}")
    
    if stdout:
        return proc.returncode, json.loads(stdout)
    return proc.returncode, {}


def check_output(data: str) -> CheckResult:
    """
    Barrière de sortie — Vérifie si les données peuvent sortir.
    
    Args:
        data: Les données à vérifier.
        
    Returns:
        CheckResult avec .allowed/.blocked/.reason
        
    Usage:
        result = check_output(output_data)
        if result.blocked:
            # Blocage — redaction explicite si chemin autorisé
            pass
    """
    exit_code, raw = _run("check", data)
    sensitivity = raw.get("sensitivity", "unknown")
    
    if exit_code == 0:
        return CheckResult.ok(sensitivity, raw)
    else:
        reason = raw.get("error", "blocked by policy")
        return CheckResult.denied(reason, sensitivity, raw)


def detect_secrets(data: str) -> DetectResult:
    """
    Détecte les secrets dans les données.
    
    Args:
        data: Les données à scanner.
        
    Returns:
        DetectResult avec .secrets_found (int), .items (list)
    """
    _, raw = _run("detect", data)
    return DetectResult(
        secrets_found=raw.get("secrets_found", 0),
        items=raw.get("items", []),
        raw=raw,
    )


def redact_if_needed(data: str) -> str:
    """
    Redacte les secrets (usage explicite, pas automatique).
    
    Args:
        data: Les données à nettoyer.
        
    Returns:
        Les données avec secrets remplacés par [REDACTED].
        
    Note:
        N'appeler que sur un chemin explicitement autorisé.
        Le check() doit être fait avant, séparément.
    """
    _, raw = _run("redact", data)
    return raw.get("output", data)


# ---------------------------------------------------------------------------
# Compatibilité ignis_exec_runner.py
# ---------------------------------------------------------------------------

class ExecutionBlocked(Exception):
    """Exception levée quand une sortie est bloquée par KeepGate."""
    pass


def safe_output(data: str, allow_redact: bool = False) -> str:
    """
    Contrôle de sortie pour ignis_exec_runner.py.
    
    Args:
        data: Les données de sortie de l'action.
        allow_redact: Si True, redacte automatiquement si bloqué.
                      Si False, lève ExecutionBlocked (default).
    
    Returns:
        Les données (inchangées si autorisées, ou redactées si allow_redact=True).
        
    Raises:
        ExecutionBlocked: si bloqué et allow_redact=False.
    """
    result = check_output(data)
    
    if result.blocked:
        if allow_redact:
            return redact_if_needed(data)
        else:
            raise ExecutionBlocked(result.reason)
    
    return data


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    
    data = sys.stdin.read() if not sys.stdin.isatty() else \
        "Test output with key sk-abc123def456ghi789jkl012mno345pqr678stu901"
    
    print("=== Check ===")
    r = check_output(data)
    print(f"  allowed: {r.allowed}")
    print(f"  blocked: {r.blocked}")
    print(f"  reason: {r.reason}")
    print(f"  sensitivity: {r.sensitivity}")
    
    print("\n=== Detect ===")
    d = detect_secrets(data)
    print(f"  secrets_found: {d.secrets_found}")
    print(f"  items: {d.items}")
    
    print("\n=== Redact ===")
    print(f"  {redact_if_needed(data)}")
    
    print("\n=== safe_output (allow_redact=False) ===")
    try:
        print(f"  {safe_output(data)}")
    except ExecutionBlocked as e:
        print(f"  BLOCKED: {e}")
    
    print("\n=== safe_output (allow_redact=True) ===")
    print(f"  {safe_output(data, allow_redact=True)}")

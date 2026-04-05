"""
KeepGate Python Wrapper — Non canonique mais supporté.

Ce module est un convenience wrapper autour de la CLI KeepGate.
Le contrat canonique reste CONTRACT_V1.md (CLI JSON + codes de sortie).

Ce wrapper ne doit pas :
- Être considéré comme l'interface officielle
- Masquer les codes de sortie
- Imposer une politique de redaction automatique

Ce wrapper peut être utilisé pour :
- Simplifier l'appel depuis Python
- Garder la logique d'appel dans un seul endroit
- Faciliter les tests unitaires
"""

import json
import subprocess
import shutil
from pathlib import Path
from typing import Optional


class KeepGateError(Exception):
    """Erreur KeepGate (système ou métier)."""
    pass


class KeepGateBlocked(KeepGateError):
    """Sortie bloquée par la politique KeepGate (exit 1)."""
    pass


class KeepGate:
    """
    Wrapper Python pour KeepGate CLI.
    
    Usage recommandé :
        kg = KeepGate("./target/release/keepgate")
        
        # Check (barrière de sortie)
        ok, details = kg.check("donnée à vérifier")
        if not ok:
            # Blocage — redaction explicite, pas automatique
            cleaned = kg.redact("donnée à vérifier")
    """
    
    def __init__(self, binary_path: Optional[str] = None):
        if binary_path:
            self.binary = Path(binary_path)
        else:
            found = shutil.which("keepgate")
            if found:
                self.binary = Path(found)
            else:
                # Chercher dans le workspace
                workspace_bin = Path(__file__).parent / "target" / "release" / "keepgate"
                if workspace_bin.exists():
                    self.binary = workspace_bin
                else:
                    raise KeepGateError(
                        "Binaire keepgate introuvable. "
                        "Compiler avec 'cargo build --release' ou ajouter au PATH."
                    )
    
    def _run(self, command: str, data: str) -> tuple[int, dict]:
        """
        Exécute une commande keepgate.
        
        Returns:
            (exit_code, json_result)
            
        Raises:
            KeepGateError: si timeout ou erreur système (exit 2, 3)
        """
        try:
            result = subprocess.run(
                [str(self.binary), command],
                input=data.encode("utf-8"),
                capture_output=True,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            raise KeepGateError("Timeout (>10s)")
        
        stdout = result.stdout.decode("utf-8").strip()
        
        if result.returncode == 2:
            raise KeepGateError(f"Erreur d'entrée: {result.stderr.decode().strip()}")
        if result.returncode == 3:
            raise KeepGateError(f"Timeout: {result.stderr.decode().strip()}")
        if result.returncode == 99:
            raise KeepGateError(f"Erreur interne: {result.stderr.decode().strip()}")
        
        if stdout:
            return result.returncode, json.loads(stdout)
        else:
            return result.returncode, {}
    
    def classify(self, data: str) -> dict:
        """
        Classifie les données.
        
        Returns:
            dict avec 'sensitivity', 'source', 'id', 'created_at'
        """
        _, result = self._run("classify", data)
        return result
    
    def detect(self, data: str) -> dict:
        """
        Détecte les secrets.
        
        Returns:
            dict avec 'secrets_found' (int), 'items' (list)
        """
        _, result = self._run("detect", data)
        return result
    
    def check(self, data: str) -> tuple[bool, dict]:
        """
        Barrière de sortie — Vérifie si les données peuvent sortir.
        
        Returns:
            (autorise, details)
            - autorise=True : sortie OK
            - autorise=False : bloqué (details contient la raison)
        
        Note:
            Ne pas redacte automatiquement. Si bloqué, l'appelant
            décide explicitement d'appeler redact().
        """
        exit_code, result = self._run("check", data)
        return exit_code == 0, result
    
    def redact(self, data: str) -> str:
        """
        Redacte les secrets (usage explicite, pas automatique).
        
        Returns:
            Les données nettoyées avec [REDACTED]
        """
        _, result = self._run("redact", data)
        return result.get("output", data)


# Convenience functions (utilisent le binaire par défaut)
_default_instance = None

def _get_instance():
    global _default_instance
    if _default_instance is None:
        _default_instance = KeepGate()
    return _default_instance


def check(data: str) -> tuple[bool, dict]:
    """Vérifie si les données peuvent sortir."""
    return _get_instance().check(data)


def redact(data: str) -> str:
    """Redacte les secrets (usage explicite)."""
    return _get_instance().redact(data)


if __name__ == "__main__":
    import sys
    data = sys.stdin.read() if not sys.stdin.isatty() else "test sk-abc123def456ghi789jkl012mno345pqr678stu901"
    kg = KeepGate()
    print("classify:", kg.classify(data))
    print("detect:", kg.detect(data))
    ok, details = kg.check(data)
    print("check:", "OK" if ok else "BLOCKED", details)
    print("redact:", kg.redact(data))

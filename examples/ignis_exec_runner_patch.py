"""
═══════════════════════════════════════════════════════════════════════════
PATCH KEEPGATE — À copier dans ignis_exec_runner.py
═══════════════════════════════════════════════════════════════════════════

Étape 1 : Copier keepgate_adapter.py dans Ignis-Exec-v0/
Étape 2 : Ajouter l'import ci-dessous en haut de ignis_exec_runner.py
Étape 3 : Wrapper la fonction qui retourne le résultat de l'action
Étape 4 : Tester les 3 cas de validation

═══════════════════════════════════════════════════════════════════════════
"""

# ═══════════════════════════════════════════════════════════════════════════
# ÉTAPE 1 — IMPORT (à ajouter en haut de ignis_exec_runner.py)
# ═══════════════════════════════════════════════════════════════════════════

from keepgate_adapter import safe_output, ExecutionBlocked


# ═══════════════════════════════════════════════════════════════════════════
# ÉTAPE 2 — WRAPPER (à intégrer dans la fonction d'exécution)
# ═══════════════════════════════════════════════════════════════════════════

def execute_action(action_name: str, params: dict) -> dict:
    """
    Exécution d'une action avec contrôle KeepGate.
    
    Remplace la fonction existante ou la wrapper.
    """
    # 1. Exécution de l'action (logique existante)
    output = _run_action(action_name, params)  # <-- votre logique existante
    
    # 2. KeepGate : contrôle de sortie
    try:
        output = safe_output(output, allow_redact=False)  # Mode strict
    except ExecutionBlocked as e:
        return {
            "status": "blocked_by_keepgate",
            "action": action_name,
            "reason": e.reason,
            "sensitivity": e.sensitivity,
        }
    
    # 3. Retour normal
    return {"status": "success", "output": output}


# ═══════════════════════════════════════════════════════════════════════════
# ÉTAPE 3 — TESTS (à ajouter dans les tests de ignis_exec_runner.py)
# ═══════════════════════════════════════════════════════════════════════════

def test_keepgate_clean():
    """Cas 1 : sortie propre → passe."""
    result = execute_action("test_action_clean", {})
    assert result["status"] == "success"
    assert "output" in result


def test_keepgate_secret_blocked():
    """Cas 2 : secret → bloqué."""
    result = execute_action("test_action_with_secret", {})
    assert result["status"] == "blocked_by_keepgate"
    assert "reason" in result
    assert result["sensitivity"] == "secret"


def test_keepgate_redact_path():
    """Cas 3 : redact explicite (chemin autorisé uniquement)."""
    # Fonction dédiée aux chemins autorisés
    from keepgate_adapter import redact_if_needed
    output = "clé sk-abc123def456ghi789jkl012mno345pqr678stu901"
    cleaned = redact_if_needed(output)
    assert "[REDACTED]" in cleaned
    assert "sk-" not in cleaned

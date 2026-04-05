"""
Patch d'intégration KeepGate pour ignis_exec_runner.py

Ce fichier montre le pattern exact d'intégration.
À adapter selon la structure réelle de ignis_exec_runner.py.

═══════════════════════════════════════════════════════════════════════════
ÉTAPE 1 — Importer l'adaptateur
═══════════════════════════════════════════════════════════════════════════

Ajouter en haut de ignis_exec_runner.py :

    from keepgate_adapter import safe_output, ExecutionBlocked

═══════════════════════════════════════════════════════════════════════════
ÉTAPE 2 — Ajouter le contrôle de sortie
═══════════════════════════════════════════════════════════════════════════

Dans la fonction qui exécute les actions et retourne le résultat,
ajouter le contrôle AVANT de retourner/exécuter la sortie.

═══════════════════════════════════════════════════════════════════════════
"""

# ---------------------------------------------------------------------------
# Patch type pour ignis_exec_runner.py
# ---------------------------------------------------------------------------

# AJOUTER cet import en haut du fichier :
# from keepgate_adapter import safe_output, ExecutionBlocked

# AJOUTER cette fonction helper :
def _keepgate_check(output: str, log=None) -> str:
    """
    Contrôle de sortie via KeepGate.
    
    Args:
        output: La sortie de l'action à vérifier.
        log: Logger optionnel.
        
    Returns:
        La sortie (inchangée si autorisée).
        
    Raises:
        ExecutionBlocked: si la sortie est bloquée.
    """
    try:
        return safe_output(output, allow_redact=False)  # Mode strict par défaut
    except ExecutionBlocked as e:
        if log:
            log.warning(f"KeepGate: sortie bloquée — {e}")
        raise


# REMPLACER/WRAPPER la fonction existante qui retourne le résultat :
#
# AVANT :
#   def execute_action(action_name: str, params: dict) -> dict:
#       result = _run_action(action_name, params)
#       return {"status": "success", "output": result}
#
# APRÈS :
#   def execute_action(action_name: str, params: dict) -> dict:
#       result = _run_action(action_name, params)
#       
#       # KeepGate : contrôle de sortie
#       try:
#           result = _keepgate_check(result, log=logger)
#       except ExecutionBlocked as e:
#           return {
#               "status": "blocked_by_keepgate",
#               "action": action_name,
#               "reason": str(e),
#           }
#       
#       return {"status": "success", "output": result}


# ---------------------------------------------------------------------------
# Alternative : redaction explicite (chemin autorisé)
# ---------------------------------------------------------------------------

# Si un chemin spécifique autorise la redaction :
#
# def execute_action_with_redact(action_name: str, params: dict) -> dict:
#     result = _run_action(action_name, params)
#     
#     # KeepGate : redaction explicite (seulement sur ce chemin)
#     try:
#         result = safe_output(result, allow_redact=False)
#     except ExecutionBlocked:
#         # Chemin explicitement autorisé pour redaction
#         result = safe_output(result, allow_redact=True)
#         logger.info(f"KeepGate: sortie redactée pour action {action_name}")
#     
#     return {"status": "success", "output": result}


# ---------------------------------------------------------------------------
# Test unitaire pour l'intégration
# ---------------------------------------------------------------------------

# AVANT :
#   def test_execute_action():
#       result = execute_action("some_action", {})
#       assert result["status"] == "success"
#
# APRÈS :
#   def test_execute_action_clean():
#       """Sortie propre → succès."""
#       result = execute_action("some_action", {})
#       assert result["status"] == "success"
#
#   def test_execute_action_blocked():
#       """Secret dans la sortie → blocage."""
#       result = execute_action("action_with_secret", {})
#       assert result["status"] == "blocked_by_keepgate"
#       assert "reason" in result


# ---------------------------------------------------------------------------
# Checklist d'intégration
# ---------------------------------------------------------------------------

# [ ] 1. keepgate_adapter.py copié dans le projet IGNIS
# [ ] 2. Binaire keepgate compilé et accessible
# [ ] 3. Import ajouté dans ignis_exec_runner.py
# [ ] 4. _keepgate_check() ajouté ou wrapper de la fonction existante
# [ ] 5. Test avec sortie propre → passe
# [ ] 6. Test avec secret → bloqué
# [ ] 7. Vérifier les logs (blocked_by_keepgate visible)
# [ ] 8. Mode strict par défaut (allow_redact=False) conservé

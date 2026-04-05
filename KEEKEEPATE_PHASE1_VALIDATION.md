# KEEPGATE_PHASE1_VALIDATION.md — Note de validation

**Date :** 2026-04-05  
**Statut :** Gel fonctionnel Phase 1/1.1  
**Prochain pas :** Intégration réelle dans IGNIS + validation terrain

---

## 1. Point d'injection

**Fichier :** `Ignis-Exec-v0/ignis_exec_runner.py`  
**Position :** Avant toute sortie/exécution d'action  
**Fonction cible :** Celle qui exécute les actions et retourne le résultat

---

## 2. Politique par défaut

| Paramètre | Valeur | Signification |
|-----------|--------|---------------|
| `allow_redact` | `False` | Blocage strict par défaut |
| Mode | deny-all | Secrets → blocage, pas de redaction automatique |
| Sensitivity default | `Private` | Toute donnée non classée = privée |
| Point d'injection | unique | `ignis_exec_runner.py` seulement |

---

## 3. Cas testés (validation terrain)

### Cas 1 — Sortie propre
- **Entrée :** `"Résultat du calcul : 42"`
- **Attendu :** Passe, exécution nominale inchangée
- **Statut :** ⬜ À valider en exécution réelle

### Cas 2 — Secret détecté, mode strict
- **Entrée :** `"clé API sk-abc123..."`
- **Attendu :** `ExecutionBlocked`, log `[KeepGate] sortie bloquée`, aucune exécution aval
- **Statut :** ⬜ À valider en exécution réelle

### Cas 3 — Secret détecté, redact autorisée
- **Entrée :** `"clé API sk-abc123..."` avec `allow_redact=True`
- **Attendu :** Sortie nettoyée `"clé API [REDACTED]"`, exécution autorisée
- **Statut :** ⬜ À valider en exécution réelle

---

## 4. Résultats (à remplir après test)

| Cas | Entrée | Sortie observée | Comportement | OK ? |
|-----|--------|-----------------|--------------|------|
| 1. Sortie propre | | | | ⬜ |
| 2. Secret strict | | | | ⬜ |
| 3. Secret redact | | | | ⬜ |

---

## 5. Limites connues (Phase 1.1)

- Pas de Memory Guard (Phase 2)
- Pas d'Input Sanitizer (Phase 2)
- Pas d'Audit Trail avancé (Phase 2)
- Pas de politique multi-niveaux local/VPS
- Seuls 6 patterns de secrets (OpenAI, AWS, GCP, JWT, private keys, passwords)
- Pas de support multi-langues pour les secrets
- CLI locale uniquement (pas de service réseau)

---

## 6. Checklist d'intégration

- [ ] `keepgate_adapter.py` copié dans `Ignis-Exec-v0/`
- [ ] Binaire `keepgate` compilé et accessible (Windows: `keepgate.exe`)
- [ ] Import ajouté dans `ignis_exec_runner.py`
- [ ] `_keepgate_check()` ou wrapper ajouté
- [ ] Test Cas 1 (sortie propre) — passe
- [ ] Test Cas 2 (secret strict) — bloqué + log
- [ ] Test Cas 3 (secret redact) — nettoyé + exécuté
- [ ] Logs vérifiés (blocked_by_keepgate visible)
- [ ] Mode strict par défaut conservé

---

## 7. Critères d'ouverture Phase 2

Phase 2 (Memory Guard, Input Sanitizer, Audit Trail) ne s'ouvre que si :

1. Les 3 cas de validation terrain sont OK
2. Le comportement est documenté et stable
3. Aucun contournement de la politique strict par défaut n'est observé
4. Les logs de blocage sont traçables

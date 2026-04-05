# CONTRACT_V1.md — Contrat d'interface KeepGate CLI v1.0

**Version :** 1.0  
**Date :** 2026-04-05  
**Stabilité :** Stable — ne change pas sans incrémentation de version

---

## Principe fondamental

KeepGate V1 est une **barrière de sortie**.  
Par défaut, il **bloque**. La redaction est un choix explicite, pas un fallback.

```
donnée → keepgate check → {ok | blocked}
donnée → keepgate redact → {donnée nettoyée}  (choix explicite, pas automatique)
```

---

## Contrat standard

Chaque commande respecte :

- **Entrée :** stdin, bytes UTF-8
- **Sortie :** stdout, JSON valide
- **Erreurs métier :** exit 1, stderr avec raison
- **Erreurs système :** exit 2 (entrée) ou 3 (timeout)
- **Timeout :** 10 secondes maximum

---

## Commandes

### `classify`

**Entrée :** données brutes (stdin)  
**Sortie :** JSON

```json
{
  "sensitivity": "private",
  "source": "User",
  "id": "uuid-v4",
  "created_at": 1234567890
}
```

**Valeurs `sensitivity` :**

| Valeur | Signification |
|--------|---------------|
| `public` | Accessible sans restriction |
| `internal` | Interne à l'écosystème |
| `private` | Données personnelles/utilisateur (DÉFAUT) |
| `secret` | Credentials, API keys, tokens |

**Exit codes :**
- 0 : toujours (classification non bloquante)
- 2 : erreur d'entrée (stdin illisible)

---

### `detect`

**Entrée :** données brutes (stdin)  
**Sortie :** JSON

```json
{
  "secrets_found": 2,
  "items": [
    {
      "pattern_type": "OpenAiKey",
      "location": 14,
      "confidence": 0.95
    },
    {
      "pattern_type": "AwsKey",
      "location": 89,
      "confidence": 0.90
    }
  ]
}
```

**`pattern_type` valides :**

| Type | Pattern | Exemple |
|------|---------|---------|
| `OpenAiKey` | `sk-...` (48+ chars) | `sk-abc123def456...` |
| `AwsKey` | `AKIA...` | `AKIAIOSFODNN7EXAMPLE` |
| `GcpKey` | `AIza...` | `AIzaSyA1b2C3d4E5f6...` |
| `Jwt` | `eyJ...` | `eyJhbGciOiJIUzI1NiIs...` |
| `PrivateKey` | `-----BEGIN...` | `-----BEGIN RSA PRIVATE KEY-----` |
| `Password` | patterns divers | `password: secret123` |

**Exit codes :**
- 0 : aucun secret trouvé
- 1 : secrets trouvés (informationnel, pas une erreur)
- 2 : erreur d'entrée

---

### `check`

**Entrée :** données brutes (stdin)  
**Sortie :** JSON  
**Politique :** deny-all (Mode 1)

```json
// Autorisé
{"status": "ok", "sensitivity": "private"}

// Bloqué
{"status": "blocked", "error": "Secret data denied", "sensitivity": "secret"}
```

**Règles de décision :**

| Sensitivity | Destination | Résultat |
|-------------|-------------|----------|
| `secret` | Message/Api | ❌ bloqué |
| `secret` | Log/File | ✅ ok |
| `private` | toute | ✅ ok |
| `internal` | toute | ✅ ok |
| `public` | toute | ✅ ok |
| données contenant secrets non taggés | Message/Api | ❌ bloqué |

**Exit codes :**
- 0 : sortie autorisée
- 1 : sortie bloquée (pas une erreur système — c'est le métier qui dit non)
- 2 : erreur d'entrée

**Point clé :** Exit 1 = décision métier, pas erreur. Le caller doit vérifier stdout pour connaître la raison.

---

### `redact`

**Entrée :** données brutes (stdin)  
**Sortie :** JSON  
**Usage :** option explicite, pas fallback automatique

```json
// Secrets détectés et redactés
{
  "status": "redacted",
  "fields_redacted": 1,
  "patterns_found": ["openai_key"],
  "output": "my key [REDACTED]"
}

// Aucun secret
{
  "status": "clean",
  "output": "données inchangées"
}
```

**Exit codes :**
- 0 : toujours (redaction non bloquante)
- 2 : erreur d'entrée

**Important :** `redact` ne décide pas si la sortie est autorisée. Il nettoie seulement. L'appelant doit décider.

---

### `version`

**Entrée :** rien  
**Sortie :** texte brut (pas JSON)

```
keepgate v1.0.0
```

**Exit code :** 0

---

## Matrice d'erreur

| Situation | Exit | stderr | stdout |
|-----------|------|--------|--------|
| Succès | 0 | — | JSON |
| Bloqué (métier) | 1 | raison | JSON avec `status: blocked` |
| Entrée illisible | 2 | `Error: cannot read stdin` | — |
| Timeout (>10s) | 3 | `Error: timeout` | — |
| Bug interne | 99 | `Error: internal` | — |

---

## Intégration dans IGNIS

### Point d'injection recommandé : `ignis_exec_runner.py`

```python
# keepgate.py — wrapper non canonique (convenience)
# Le contrat canonique reste la CLI JSON

import subprocess
import json
from pathlib import Path

KEEKEEPATE_BIN = Path(__file__).parent / "target" / "release" / "keepgate"

def check_output(data: str) -> tuple[bool, dict]:
    """
    Vérifie si les données peuvent sortir.
    Returns: (autorise: bool, details: dict)
    """
    proc = subprocess.run(
        [str(KEEKEEPATE_BIN), "check"],
        input=data.encode("utf-8"),
        capture_output=True,
        timeout=10,
    )
    result = json.loads(proc.stdout)
    return proc.returncode == 0, result

def redact_output(data: str) -> str:
    """Redacte les secrets (usage explicite, pas automatique)."""
    proc = subprocess.run(
        [str(KEEKEEPATE_BIN), "redact"],
        input=data.encode("utf-8"),
        capture_output=True,
        timeout=10,
    )
    result = json.loads(proc.stdout)
    return result.get("output", data)
```

### Usage dans `ignis_exec_runner.py`

```python
# Dans ignis_exec_runner.py, avant toute exécution de sortie :
from keepgate import check_output, redact_output

def safe_execute(action_output: str) -> str:
    autorise, details = check_output(action_output)
    if autorise:
        return action_output
    else:
        # Blocage — loguer, ne pas exécuter
        log.warning(f"Sortie bloquée: {details}")
        raise ExecutionBlocked(details["error"])
```

---

## Ce qui est hors scope V1

- Memory Guard (Phase 2)
- Input Sanitizer (Phase 2)
- Audit Trail (Phase 2)
- API réseau
- FFI
- Politiques de redaction automatique

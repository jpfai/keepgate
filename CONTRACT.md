# CONTRACT.md — Contrat d'entrée/sortie KeepGate CLI

## Principe

Chaque commande lit stdin en bytes UTF-8, produit stdout en JSON.  
Exit code 0 = succès, 1 = blocage ou erreur.

---

## Commandes

### `keepgate classify`

**Entrée :** données brutes (stdin)  
**Sortie :** JSON

```json
{
  "sensitivity": "private",
  "source": "User",
  "id": "uuid-v4",
  "created_at": 1775411091
}
```

**Valeurs de `sensitivity` :**
| Valeur | Description |
|--------|-------------|
| `public` | Accessible sans restriction |
| `internal` | Interne à l'écosystème |
| `private` | Données personnelles/utilisateur (default) |
| `secret` | Credentials, API keys, tokens |

**Exit code :** toujours 0

---

### `keepgate detect`

**Entrée :** données brutes (stdin)  
**Sortie :** JSON

```json
{
  "secrets_found": 1,
  "items": [
    {
      "pattern_type": "OpenAiKey",
      "location": 14,
      "confidence": 0.95
    }
  ]
}
```

**Exit code :** 0 si aucun secret, 1 si secrets trouvés

**Pattern types :**
- `OpenAiKey` — sk-...
- `AwsKey` — AKIA...
- `GcpKey` — AIza...
- `Jwt` — eyJ...
- `PrivateKey` — -----BEGIN...
- `Password` — patterns mot de passe

---

### `keepgate check`

**Entrée :** données brutes (stdin)  
**Sortie :** JSON  
**Politique :** deny-all (bloque les secrets vers destinations sensibles)

```json
// OK
{"status": "ok", "sensitivity": "private"}

// Bloqué
{"status": "blocked", "error": "sensitivity violation: ...", "sensitivity": "secret"}
```

**Exit code :** 0 si OK, 1 si bloqué

**Règles :**
- `Secret` → Message/Api : **bloqué** (deny-all)
- `Secret` → Log/File : **autorisé**
- `Private` → toute destination : **autorisé**
- Données contenant des secrets non taggés → Message/Api : **bloqué**

---

### `keepgate redact`

**Entrée :** données brutes (stdin)  
**Sortie :** JSON

```json
{
  "status": "redacted",
  "fields_redacted": 1,
  "patterns_found": ["openai_key"],
  "output": "my key [REDACTED]"
}
```

```json
// Si aucun secret
{
  "status": "clean",
  "output": "données inchangées"
}
```

**Exit code :** toujours 0

---

### `keepgate version`

**Entrée :** rien  
**Sortie :** texte brut

```
keepgate v0.1.0
```

**Exit code :** 0

---

## Contrat d'erreur

- Erreur d'entrée (stdin illisible) : stderr + exit 2
- Timeout (>10s) : stderr + exit 3
- JSON invalide en sortie : ne devrait jamais arriver (bug)

## Intégration type

### Python (IGNIS)
```python
import subprocess, json

def keepgate_check(data: str) -> dict:
    result = subprocess.run(
        ["keepgate", "check"],
        input=data.encode(),
        capture_output=True
    )
    return json.loads(result.stdout)
```

### PowerShell (Windows)
```powershell
$data | keepgate check | ConvertFrom-Json
```

### Shell (VPS)
```bash
echo "$data" | keepgate check | jq .
```

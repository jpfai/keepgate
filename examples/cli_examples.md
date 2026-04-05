# CLI Examples — KeepGate v1.0

Exemples concrets d'utilisation de la CLI KeepGate.

---

## classify

### Données normales
```bash
$ echo "Bonjour Jean-Paul, voici le rapport quotidien" | ./target/release/keepgate classify
{"created_at":1775411091,"id":"abc-123","sensitivity":"private","source":"User"}
```

### Données avec secret
```bash
$ echo "Voici la clé: sk-abc123def456ghi789jkl012mno345pqr678stu901" | ./target/release/keepgate classify
{"created_at":1775411092,"id":"def-456","sensitivity":"secret","source":"User"}
```

### Données publiques
```bash
$ echo "La documentation publique dit que..." | ./target/release/keepgate classify
{"created_at":1775411093,"id":"ghi-789","sensitivity":"private","source":"User"}
```

---

## detect

### Clé OpenAI détectée
```bash
$ echo "Ma clé est sk-abc123def456ghi789jkl012mno345pqr678stu901" | ./target/release/keepgate detect
{"items":[{"confidence":0.95,"location":14,"pattern_type":"OpenAiKey"}],"secrets_found":1}
```
Exit code: 1 (secret trouvé)

### AWS Key
```bash
$ echo "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE" | ./target/release/keepgate detect
{"items":[{"confidence":0.90,"location":15,"pattern_type":"AwsKey"}],"secrets_found":1}
```
Exit code: 1

### Clean
```bash
$ echo "Rien de sensible ici" | ./target/release/keepgate detect
{"secrets_found":0}
```
Exit code: 0

### Multiple secrets
```bash
$ echo "openai sk-abc123def456ghi789jkl012mno345pqr678stu901 and aws AKIAIOSFODNN7EXAMPLE" | ./target/release/keepgate detect
{"items":[{"confidence":0.95,"location":7,"pattern_type":"OpenAiKey"},{"confidence":0.90,"location":72,"pattern_type":"AwsKey"}],"secrets_found":2}
```
Exit code: 1

---

## check

### Sortie propre (autorisée)
```bash
$ echo "Le résultat est 42" | ./target/release/keepgate check
{"status":"ok","sensitivity":"private"}
```
Exit code: 0

### Clé secrète (bloquée)
```bash
$ echo "La clé API est sk-abc123def456ghi789jkl012mno345pqr678stu901" | ./target/release/keepgate check
{"error":"secret detected in output","sensitivity":"secret","status":"blocked"}
```
Exit code: 1

### Interpretation de l'exit code
```bash
$ if echo "safe data" | ./target/release/keepgate check > /dev/null; then
    echo "AUTORISÉ"
else
    echo "BLOQUÉ"
fi
AUTORISÉ
```

```bash
$ if echo "key sk-abc123" | ./target/release/keepgate check > /dev/null; then
    echo "AUTORISÉ"
else
    echo "BLOQUÉ"
fi
BLOQUÉ
```

---

## redact

### Secrets redactés
```bash
$ echo "API key: sk-abc123def456ghi789jkl012mno345pqr678stu901" | ./target/release/keepgate redact
Redacted 1 secrets
{"fields_redacted":1,"output":"API key: [REDACTED]","patterns_found":["openai_key"],"status":"redacted"}
```

### Clean (pas de redaction)
```bash
$ echo "Pas de secrets ici" | ./target/release/keepgate redact
{"output":"Pas de secrets ici\n","status":"clean"}
```

### Redaction sélective
```bash
$ echo "email test@example.com et clé sk-abc123def456ghi789jkl012mno345pqr678stu901" | ./target/release/keepgate redact
Redacted 1 secrets
{"fields_redacted":1,"output":"email test@example.com et clé [REDACTED]\n","patterns_found":["openai_key"],"status":"redacted"}
```

---

## Patterns d'usage

### "Check then redact" — Usage explicite recommandé
```bash
#!/bin/bash
# ignis_check_output.sh — Contrôle de sortie IGNIS

OUTPUT="$1"

# Étape 1 : Vérifier
if echo "$OUTPUT" | ./target/release/keepgate check > /tmp/keepgate_check.json 2>/dev/null; then
    # OK, la sortie est propre
    echo "$OUTPUT"
else
    # Bloqué — redacter explicitement
    echo "⚠️  Sortie bloquée, redaction en cours..." >&2
    CLEANED=$(echo "$OUTPUT" | ./target/release/keepgate redact | python3 -c "import sys,json; print(json.load(sys.stdin)['output'])")
    echo "$CLEANED"
fi
```

### Python integration
```python
import subprocess
import json

def check_or_redact(data: str) -> tuple[bool, str]:
    """Check d'abord, redacte seulement si bloqué (usage explicite)."""
    # 1. Check
    proc = subprocess.run(
        ["./target/release/keepgate", "check"],
        input=data.encode(),
        capture_output=True
    )
    if proc.returncode == 0:
        return True, data  # Sortie autorisée
    
    # 2. Bloqué — redacte explicitement
    proc = subprocess.run(
        ["./target/release/keepgate", "redact"],
        input=data.encode(),
        capture_output=True
    )
    result = json.loads(proc.stdout)
    return False, result.get("output", data)
```

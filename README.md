# KeepGate

Data protection layer for agent ecosystems.  
Rust • CLI-first • Generic • Barrière de sortie

## Principe

KeepGate V1 est une **barrière de sortie**. Par défaut, il **bloque** les secrets. La redaction est un choix explicite, pas un fallback.

```
donnée → keepgate check → {ok | blocked}
donnée → keepgate redact → {donnée nettoyée}  (choix explicite)
```

## Modules

| Module | Rôle |
|--------|------|
| `data_classifier` | Tags de sensibilité (Public/Internal/Private/Secret), default = Private |
| `leak_detector` | Détection de patterns secrets (OpenAI, AWS, GCP, JWT, private keys) |
| `output_gate` | Contrôle des sorties : blocage des secrets |
| `approvals` | Politique de décision (deny-all, auto-approve) |

## Installation

```bash
git clone <repo> && cd keepgate
cargo build --release
# Binaire : target/release/keepgate
```

## Usage rapide

```bash
echo "hello" | ./target/release/keepgate classify
# → {"sensitivity":"private", ...}

echo "key sk-abc123" | ./target/release/keepgate detect
# → {"secrets_found":1, ...} (exit 1)

echo "key sk-abc123" | ./target/release/keepgate check
# → {"status":"blocked", ...} (exit 1)

echo "key sk-abc123" | ./target/release/keepgate redact
# → {"status":"redacted", "output":"key [REDACTED]", ...}
```

## Tests

```bash
cargo test
# 35 tests — tous doivent passer
```

## Documentation

| Fichier | Contenu |
|---------|---------|
| [CONTRACT_V1.md](CONTRACT_V1.md) | Contrat d'interface V1 (le canonique) |
| [examples/cli_examples.md](examples/cli_examples.md) | Exemples concrets CLI |
| [keepgate.py](keepgate.py) | Wrapper Python (non canonique, convenience) |

## Intégration dans IGNIS

Point d'injection recommandé : **`ignis_exec_runner.py`**  
Lire [CONTRACT_V1.md § Intégration](CONTRACT_V1.md#int%C3%A9gration-dans-ignis) pour les détails.

## Architecture

```
IGNIS (Python, local)
 └── prépare sortie/action
 ↓
KeepGate (Rust, binaire)
 ├── classify → sensitivity
 ├── detect   → secrets trouvés
 ├── check    → autorise | bloque
 └── redact   → nettoie (option explicite)
 ↓
Décision structurée
 ├── allow     → exécution
 ├── deny      → blocage
 └── redact    → nettoyage explicite puis exécution
```

## Licence

MIT

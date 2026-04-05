# LIMITATIONS.md — Limites connues KeepGate V1

**Version :** 1.0  
**Date :** 2026-04-05  
**Statut :** Gel Phase 1.1

---

## 1. Garantie de couverture

KeepGate garantit le **blocage déterministe des patterns de secrets connus**.

KeepGate **ne garantit pas** l'absence totale de fuite de données.

Formulation rigoureuse :

> KeepGate does not guarantee the absence of data leaks.  
> It guarantees deterministic blocking of known sensitive patterns  
> and provides layered defenses against evasion techniques.

---

## 2. Limites techniques (V1)

### 2.1 Détection regex uniquement

**Limite :** Seuls 6 patterns sont détectés :
- OpenAI keys (`sk-...`)
- AWS keys (`AKIA...`)
- GCP keys (`AIza...`)
- JWT (`eyJ...`)
- Private keys (`-----BEGIN...`)
- Passwords (patterns divers)

**Non couvert :**
- Tokens propriétaires (formats non connus)
- Secrets courts (< 10 caractères)
- Clés sans préfixe identifiable

**Atténuation Phase 2 :** Entropie de Shannon + contexte syntaxique.

---

### 2.2 Pas de normalisation

**Limite :** Un secret encodé en base64, hex, URL-encode, ou autre format n'est pas détecté.

**Exemple :**
```
Entrée encodée : c2stYWJjMTIz  (base64 de "sk-abc123")
Résultat V1    : non détecté
Résultat V2    : détecté après décodage
```

**Atténuation Phase 2 :** Pipeline de normalisation (decode → detect).

---

### 2.3 Pas de détection fragmentée

**Limite :** Un secret découpé en morceaux échappe à la détection.

**Exemple :**
```
Entrée : "sk-" + "abc" + "123" (concaténé ou séparé)
Résultat V1 : non détecté
Résultat V2 : détecté par fenêtre glissante
```

**Atténuation Phase 3 :** Sliding window + recomposition.

---

### 2.4 Pas d'entropie

**Limite :** Les secrets sans préfixe identifiable mais à haute entropie ne sont pas détectés.

**Exemple :**
```
Entrée : token = "x7K9mP2qR5tW8vY" (16 chars, haute entropie)
Résultat V1 : non détecté
Résultat V2 : détecté si entropy > seuil
```

**Atténuation Phase 2 :** Score d'entropie de Shannon.

---

### 2.5 Pas de contexte syntaxique

**Limite :** Le contexte autour du secret n'est pas analysé.

**Exemple :**
```
Entrée : "clé API : sk-abc123..."  → détecté (par le pattern)
Entrée : "mon token personnel est xK9mP2..." → non détecté (pas de pattern)
```

**Atténuation Phase 2 :** Contexte syntaxique (`api_key=`, `token=`, `bearer`, etc.).

---

## 3. Limites architecturales

### 3.1 CLI = pas de contexte de session

**Limite :** Chaque appel CLI est indépendant. Pas de mémoire entre appels.

**Conséquence :** Impossible de détecter un secret distribué sur plusieurs sorties.

**Atténuation Phase 2 :** Memory Guard (buffer de contexte).

---

### 3.2 Pas de politique dynamique

**Limite :** La politique est codée dans le binaire (deny-all). Pas de configuration à chaud.

**Conséquence :** Pour changer de politique, il faut recompiler ou utiliser un autre ApprovalProvider.

**Atténuation Phase 2 :** Fichier de politique externe (TOML/YAML).

---

### 3.3 Pas d'audit trail

**Limite :** Les décisions de blocage ne sont pas journalisées de manière persistante.

**Conséquence :** Pas de traçabilité historique des incidents.

**Atténuation Phase 2 :** Audit Trail (log structuré).

---

## 4. Limites de déploiement

### 4.1 Binaire local uniquement

**Limite :** KeepGate doit être compilé et accessible localement.

**Conséquence :** Pas de service centralisé partagé.

**Positionnement :** C'est un choix architectural, pas une limitation accidentelle — la CLI locale évite les problèmes de transport, auth, disponibilité.

---

### 4.2 UTF-8 uniquement

**Limite :** Les données d'entrée doivent être UTF-8.

**Conséquence :** Les données binaires ou encodées autrement ne sont pas traitées.

---

## 5. Ce que KeepGate ne fait pas (par design)

| Hors scope | Raison | Solution |
|------------|--------|----------|
| Filtrage de prompts | Périmètre = sorties | Input Sanitizer (Phase 2) |
| Rails conversationnels | Périmètre = données | NeMo/Llama Guard (externe) |
| Authentification | Périmètre = contenu | IAM/credentials (infrastructure) |
| Chiffrement | Périmètre = détection | TLS/GPG (infrastructure) |
| DLP réseau | Périmètre = local | Macie/Symantec (cloud) |

---

## 6. Engagement de qualité

KeepGate s'engage à :
- Documenter explicitement chaque limite connue
- Ne jamais prétendre à une couverture qu'il n'a pas
- Évoluer par couches successives, pas par promesses

KeepGate ne s'engage pas à :
- Éliminer tous les faux négatifs
- Détecter tous les formats de secrets possibles
- Remplacer un DLP d'entreprise complet

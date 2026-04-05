"""
Tests d'intégration Python pour KeepGate adapter.

Usage :
    python -m pytest test_keepgate_adapter.py -v
    ou
    python test_keepgate_adapter.py

Prérequis :
    - Binaire keepgate compilé (target/release/keepgate)
    - Python 3.8+
"""

import json
import sys
import unittest
from pathlib import Path

# Adapter le path selon installation
sys.path.insert(0, str(Path(__file__).parent))

from keepgate_adapter import (
    check_output,
    detect_secrets,
    redact_if_needed,
    safe_output,
    ExecutionBlocked,
    _find_binary,
)


class TestCheckOutput(unittest.TestCase):
    """Test 1 : sortie propre → passe"""
    
    def test_clean_data_passes(self):
        result = check_output("Bonjour, voici le rapport quotidien.")
        self.assertTrue(result.allowed)
        self.assertFalse(result.blocked)
        self.assertIsNone(result.reason)
    
    def test_clean_data_sensitivity_is_private(self):
        result = check_output("Données normales.")
        self.assertEqual(result.sensitivity, "private")


class TestDetectSecrets(unittest.TestCase):
    """Test 2 : détection de secrets"""
    
    def test_no_secrets(self):
        result = detect_secrets("Rien de sensible ici.")
        self.assertEqual(result.secrets_found, 0)
        self.assertEqual(len(result.items), 0)
    
    def test_openai_key_detected(self):
        result = detect_secrets("Ma clé: sk-abc123def456ghi789jkl012mno345pqr678stu901")
        self.assertEqual(result.secrets_found, 1)
        self.assertEqual(result.items[0]["pattern_type"], "OpenAiKey")


class TestStrictMode(unittest.TestCase):
    """Test 3 : secret détecté + mode strict → exception"""
    
    def test_secret_blocked_strict_mode(self):
        data = "La clé API est sk-abc123def456ghi789jkl012mno345pqr678stu901"
        with self.assertRaises(ExecutionBlocked) as ctx:
            safe_output(data, allow_redact=False)
        
        self.assertIn("blocked_by_keepgate", str(ctx.exception))
        self.assertIsNotNone(ctx.exception.reason)
        self.assertIsNotNone(ctx.exception.sensitivity)
    
    def test_execution_blocked_to_dict(self):
        data = "clé: sk-abc123def456ghi789jkl012mno345pqr678stu901"
        with self.assertRaises(ExecutionBlocked) as ctx:
            safe_output(data, allow_redact=False)
        
        d = ctx.exception.to_dict()
        self.assertEqual(d["status"], "blocked_by_keepgate")
        self.assertIn("reason", d)
        self.assertIn("sensitivity", d)
    
    def test_default_is_strict(self):
        """Vérifie que le défaut est blocage strict (allow_redact=False)."""
        data = "clé: sk-abc123def456ghi789jkl012mno345pqr678stu901"
        with self.assertRaises(ExecutionBlocked):
            safe_output(data)  # pas de allow_redact = défaut strict


class TestRedactMode(unittest.TestCase):
    """Test 4 : secret détecté + redact autorisé → texte redigé"""
    
    def test_secret_redacted_when_allowed(self):
        data = "La clé API est sk-abc123def456ghi789jkl012mno345pqr678stu901"
        result = safe_output(data, allow_redact=True)
        
        self.assertNotIn("sk-abc123", result)
        self.assertIn("[REDACTED]", result)
        self.assertIn("La clé API est", result)
    
    def test_clean_data_unchanged_with_redact_allowed(self):
        data = "Pas de secrets ici."
        result = safe_output(data, allow_redact=True)
        self.assertEqual(result, data)
    
    def test_redact_if_needed_explicit(self):
        data = "key sk-abc123def456ghi789jkl012mno345pqr678stu901 end"
        result = redact_if_needed(data)
        self.assertIn("[REDACTED]", result)
        self.assertNotIn("sk-", result)


class TestBinaryNotFound(unittest.TestCase):
    """Test 5 : binaire introuvable → erreur claire et contrôlée"""
    
    def test_binary_not_found(self):
        # Monkey-patch pour simuler binaire absent
        import keepgate_adapter
        original_binary = keepgate_adapter._binary
        keepgate_adapter._binary = Path("/does/not/exist/keepgate")
        
        try:
            with self.assertRaises(FileNotFoundError):
                safe_output("test data")
        finally:
            keepgate_adapter._binary = original_binary


class TestPatchIgnisExecRunner(unittest.TestCase):
    """
    Test du pattern d'intégration dans ignis_exec_runner.py
    Vérifie le comportement attendu du code d'intégration.
    """
    
    def test_pattern_clean(self):
        """Sortie propre → exécution normale."""
        output = "Résultat du calcul : 42"
        try:
            result = safe_output(output)
            self.assertEqual(result, output)
        except ExecutionBlocked:
            self.fail("Sortie propre ne devrait pas être bloquée")
    
    def test_pattern_secret_strict(self):
        """Secret + mode strict → blocage + log."""
        output = "key sk-abc123def456ghi789jkl012mno345pqr678stu901"
        try:
            safe_output(output)
            self.fail("Secret devrait être bloqué en mode strict")
        except ExecutionBlocked as e:
            # Comportement attendu : log + retour erreur
            error_response = e.to_dict()
            self.assertEqual(error_response["status"], "blocked_by_keepgate")
            self.assertIsNotNone(error_response["reason"])
    
    def test_pattern_secret_redact_path(self):
        """Secret + chemin redact autorisé → nettoyage."""
        output = "key sk-abc123def456ghi789jkl012mno345pqr678stu901"
        cleaned = safe_output(output, allow_redact=True)
        self.assertIn("[REDACTED]", cleaned)
        self.assertNotIn("sk-", cleaned)


if __name__ == "__main__":
    unittest.main(verbosity=2)

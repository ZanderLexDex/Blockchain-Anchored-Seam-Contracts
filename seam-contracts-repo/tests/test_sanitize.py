"""Tests for sanitize_engine.py v2.2"""
import unittest
from sanitize_engine import sanitize_text, assert_clean, UnicodeSecurityError, verify_contract_text

class TestSanitizeText(unittest.TestCase):

    def test_clean_text_passes(self):
        text = "Hello, this is normal English text."
        cleaned, report = sanitize_text(text)
        self.assertEqual(cleaned, text)
        self.assertEqual(report["max_severity"], "CLEAN")

    def test_zero_width_stripped(self):
        text = "Hello\u200B world\u200D test\uFEFF"
        cleaned, report = sanitize_text(text)
        self.assertEqual(cleaned, "Hello world test")
        self.assertEqual(report["max_severity"], "CRITICAL")
        self.assertGreater(report["modifications"], 0)

    def test_confusable_whitespace_normalized(self):
        text = "Hello\u2003world"  # em-space
        cleaned, report = sanitize_text(text)
        self.assertEqual(cleaned, "Hello world")

    def test_cyrillic_homoglyph_detected(self):
        text = "H\u0435llo"  # Cyrillic е in place of Latin e
        cleaned, report = sanitize_text(text)
        self.assertEqual(cleaned, "Hello")
        self.assertEqual(report["max_severity"], "CRITICAL")

    def test_tag_characters_stripped(self):
        hidden = ''.join(chr(cp) for cp in range(0xE0001, 0xE0020))
        text = f"Normal{hidden}Text"
        cleaned, report = sanitize_text(text)
        self.assertEqual(cleaned, "NormalText")
        self.assertEqual(report["max_severity"], "CRITICAL")

    def test_emoji_skin_tone_stripped(self):
        text = "thumbs\U0001F3FB\U0001F3FDup"  # skin tone modifiers
        cleaned, report = sanitize_text(text)
        self.assertEqual(cleaned, "thumbsup")

    def test_assert_clean_raises_on_critical(self):
        text = "Hello\u200Bworld"
        with self.assertRaises(UnicodeSecurityError):
            assert_clean(text)

    def test_assert_clean_passes_clean_text(self):
        result = assert_clean("Normal text")
        self.assertEqual(result, "Normal text")

    def test_nfkc_before_homoglyph(self):
        # Mathematical bold 'a' (U+1D41A) should NFKC to 'a' in pass 3
        text = "Hello \U0001D41A"
        cleaned, report = sanitize_text(text)
        self.assertIn("a", cleaned)

    def test_control_characters_stripped(self):
        text = "Hello\x01\x02\x03World"
        cleaned, report = sanitize_text(text)
        self.assertEqual(cleaned, "HelloWorld")

    def test_newlines_preserved(self):
        text = "Line 1\nLine 2\r\nLine 3"
        cleaned, report = sanitize_text(text)
        self.assertEqual(cleaned, text)

    def test_contract_text_verification(self):
        contract = {
            "contract_id": "test",
            "version": 1,
            "description": "Clean\u200B contract"
        }
        result = verify_contract_text(contract)
        self.assertFalse(result["clean"])


class TestEmptyInput(unittest.TestCase):
    def test_empty_string(self):
        cleaned, report = sanitize_text("")
        self.assertEqual(cleaned, "")
        self.assertEqual(report["max_severity"], "CLEAN")

    def test_none_passthrough(self):
        cleaned, report = sanitize_text(None)
        self.assertIsNone(cleaned)


if __name__ == "__main__":
    unittest.main()

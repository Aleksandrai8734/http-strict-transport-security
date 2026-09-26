import unittest

from http_strict_transport_security import HSTSPolicy, parse_hsts


class ParseHstsTests(unittest.TestCase):
    def test_full_header(self):
        result = parse_hsts("max-age=63072000; includeSubDomains; preload")
        self.assertEqual(result.max_age, 63072000)
        self.assertTrue(result.include_sub_domains)
        self.assertTrue(result.preload)

    def test_max_age_only(self):
        result = parse_hsts("max-age=300")
        self.assertEqual(result.max_age, 300)
        self.assertFalse(result.include_sub_domains)
        self.assertFalse(result.preload)

    def test_directives_in_any_order(self):
        result = parse_hsts("preload; max-age=1200; includeSubDomains")
        self.assertEqual(result.max_age, 1200)
        self.assertTrue(result.include_sub_domains)
        self.assertTrue(result.preload)

    def test_case_insensitive_directives(self):
        result = parse_hsts("MAX-AGE=90; INCLUDESUBDOMAINS; PRELOAD")
        self.assertEqual(result.max_age, 90)
        self.assertTrue(result.include_sub_domains)
        self.assertTrue(result.preload)

    def test_whitespace_tolerance(self):
        result = parse_hsts("  max-age  =  450  ;  includeSubDomains  ")
        self.assertEqual(result.max_age, 450)
        self.assertTrue(result.include_sub_domains)

    def test_no_max_age_yields_none(self):
        result = parse_hsts("includeSubDomains; preload")
        self.assertIsNone(result.max_age)
        self.assertTrue(result.include_sub_domains)
        self.assertTrue(result.preload)

    def test_invalid_max_age_is_ignored(self):
        result = parse_hsts("max-age=not-a-number; includeSubDomains")
        self.assertIsNone(result.max_age)
        self.assertTrue(result.include_sub_domains)

    def test_last_max_age_wins(self):
        result = parse_hsts("max-age=10; max-age=20")
        self.assertEqual(result.max_age, 20)

    def test_empty_header(self):
        result = parse_hsts("")
        self.assertIsNone(result.max_age)
        self.assertFalse(result.include_sub_domains)
        self.assertFalse(result.preload)

    def test_unknown_directives_ignored(self):
        result = parse_hsts("max-age=600; report-uri=/hsts; foo=bar")
        self.assertEqual(result.max_age, 600)
        self.assertFalse(result.include_sub_domains)
        self.assertFalse(result.preload)

    def test_trailing_semicolons(self):
        result = parse_hsts("max-age=700;;;")
        self.assertEqual(result.max_age, 700)

    def test_quoted_max_age_value(self):
        # Browsers generally don't see this form, but we tolerate it.
        result = parse_hsts('max-age="800"')
        self.assertEqual(result.max_age, 800)

    def test_non_string_raises(self):
        with self.assertRaises(TypeError):
            parse_hsts(63072000)  # type: ignore[arg-type]

    def test_returns_hstspolicy_instance(self):
        result = parse_hsts("max-age=1")
        self.assertIsInstance(result, HSTSPolicy)


if __name__ == "__main__":
    unittest.main()

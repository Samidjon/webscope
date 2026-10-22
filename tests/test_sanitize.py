import unittest
from backend.sanitize import sanitize_body, sanitize_headers, sanitize_url


class SanitizeTests(unittest.TestCase):
    def test_sensitive_query_parameter_is_redacted(self):
        actual = sanitize_url('https://example.test/api?token=abc123&page=2')
        self.assertIn('token=%5BREDACTED%5D', actual)
        self.assertIn('page=2', actual)
        self.assertNotIn('abc123', actual)

    def test_sensitive_headers_are_redacted(self):
        actual = sanitize_headers([('Authorization', 'Bearer very-secret'), ('Accept', 'application/json')])
        self.assertEqual(actual[0][1], '[REDACTED]')
        self.assertEqual(actual[1][1], 'application/json')

    def test_sensitive_json_fields_are_redacted(self):
        actual = sanitize_body('{"username":"sam","password":"hunter2","nested":{"access_token":"abc"}}', 'application/json')
        self.assertIn('[REDACTED]', actual)
        self.assertNotIn('hunter2', actual)
        self.assertNotIn('"abc"', actual)

    def test_non_text_body_is_omitted(self):
        actual = sanitize_body('0101010101', 'application/octet-stream')
        self.assertTrue(actual.startswith('[Body omitted: non-text content'))


if __name__ == '__main__':
    unittest.main()

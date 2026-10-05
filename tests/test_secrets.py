import unittest

from agentshield.checks.secrets import check_secrets, is_placeholder, mask, shannon_entropy
from agentshield.findings import Severity

from .helpers import fake_secret, files_from, make_diff

UPPER_DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def scan(path, *lines):
    findings, notes = check_secrets(files_from(make_diff(path, list(lines))))
    return findings, notes


def rules(path, *lines):
    return [f.rule for f in scan(path, *lines)[0]]


class KnownFormatTest(unittest.TestCase):
    def test_each_provider_format(self):
        cases = {
            "secret.aws-key": "AKIA" + fake_secret(16, 1, UPPER_DIGITS),
            "secret.github-token": "ghp_" + fake_secret(36, 2),
            "secret.anthropic-key": "sk-ant-api03-" + fake_secret(90, 3),
            "secret.openai-key": "sk-proj-" + fake_secret(48, 4),
            "secret.stripe-key": "sk_live_" + fake_secret(24, 5),
            "secret.slack-token": "xoxb-" + fake_secret(12, 6, "0123456789") + "-" + fake_secret(24, 7),
            "secret.google-api-key": "AIza" + fake_secret(35, 8),
            "secret.jwt": "eyJ" + fake_secret(20, 9) + ".eyJ" + fake_secret(30, 10) + "." + fake_secret(40, 11),
        }
        for rule, key in cases.items():
            with self.subTest(rule=rule):
                self.assertEqual(rules("app/config.py", f'KEY = "{key}"'), [rule])

    def test_aws_secret_access_key_with_context(self):
        line = f'aws_secret_access_key = "{fake_secret(40, 12)}"'
        self.assertEqual(rules("settings.py", line), ["secret.aws-key"])

    def test_private_key_header(self):
        header = "-----BEGIN " + "RSA PRIVATE KEY-----"
        findings, _ = scan("deploy/id_rsa", header)
        self.assertEqual((findings[0].rule, findings[0].severity), ("secret.private-key", Severity.HIGH))

    def test_database_url_with_password(self):
        url = "postgres://app:" + fake_secret(20, 13) + "@db.prod.internal:5432/app"
        self.assertEqual(rules("config.py", f'DB = "{url}"'), ["secret.db-url"])

    def test_one_key_gives_one_finding(self):
        # The OpenAI key also sits in a secret-named variable; don't report it twice.
        key = "sk-proj-" + fake_secret(48, 14)
        self.assertEqual(rules("a.py", f'openai_api_key = "{key}"'), ["secret.openai-key"])

    def test_secret_is_masked_in_message(self):
        key = "ghp_" + fake_secret(36, 15)
        findings, _ = scan("a.py", f'token = "{key}"')
        self.assertIn("ghp_********", findings[0].message)
        self.assertNotIn(key[4:], findings[0].message)


class EntropyTest(unittest.TestCase):
    def test_entropy_values(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertEqual(shannon_entropy("abcd"), 2.0)  # 4 equally likely symbols = 2 bits
        self.assertGreater(shannon_entropy(fake_secret(32, 16)), 4.0)

    def test_random_value_in_secret_named_variable(self):
        findings, _ = scan("app.js", f'const apiKey = "{fake_secret(32, 17)}";')
        self.assertEqual((findings[0].rule, findings[0].severity), ("secret.high-entropy", Severity.MEDIUM))

    def test_env_file_without_quotes(self):
        self.assertEqual(rules(".env", f"PAYMENT_SECRET={fake_secret(30, 18)}"), ["secret.high-entropy"])
        self.assertEqual(rules("k8s/app.yaml", f"  client_secret: {fake_secret(30, 19)}"),
                         ["secret.high-entropy"])

    def test_bare_assignments_ignored_in_code(self):
        # In Python, `token = some_function_call` is code, not a value.
        self.assertEqual(rules("a.py", "token = get_token_from_vault_2024()"), [])


class FalsePositiveTest(unittest.TestCase):
    def test_placeholders(self):
        lines = [
            'OPENAI_API_KEY = "sk-your-key-here-xxxxxxxxxxxxxxxx"',
            'aws_key = "AKIAIOSFODNN7EXAMPLE"',  # the key from the AWS docs
            'api_key = "<YOUR_API_KEY_GOES_HERE_123>"',
            'secret = "${SECRET_FROM_ENVIRONMENT_1}"',
            'token = "0000000000000000000000000"',
            'password = "changeme-before-deploy-123"',
        ]
        self.assertEqual(rules("app.py", *lines), [])

    def test_words_and_references_are_not_secrets(self):
        lines = [
            'SECRET_KEY_SETTING = "app.settings.SECRET_KEY"',   # no digits: a reference
            'token_url = "https://auth.example.com/oauth2/token/v1"',
            'password_field = "password_confirmation"',
            'TOKEN = os.environ["GITHUB_TOKEN"]',
            'auth_token_header = "X-Auth-Token"',
            'api_key = process.env.API_KEY_V2',
        ]
        self.assertEqual(rules("app.py", *lines), [])

    def test_local_dev_database_urls(self):
        self.assertEqual(rules("docker-compose.yml",
                               "DATABASE_URL: postgres://postgres:postgres@db:5432/app",
                               "REDIS_URL: redis://user:s3cretLocalOnly99@localhost:6379"), [])

    def test_lowercase_words_after_sk_are_not_openai_keys(self):
        self.assertEqual(rules("style.css", ".sk-loading-spinner-container-large { }"), [])

    def test_stripe_test_keys_ignored(self):
        self.assertEqual(rules("pay.py", f'stripe.api_key = "sk_test_{fake_secret(24, 20)}"'), [])

    def test_lockfiles_skipped(self):
        line = f'"integrity": "sha512-{fake_secret(80, 21)}==",'
        self.assertEqual(rules("package-lock.json", line), [])

    def test_test_files_downgraded_to_low_with_note(self):
        key = "AKIA" + fake_secret(16, 22, UPPER_DIGITS)
        findings, notes = scan("tests/test_upload.py", f'KEY = "{key}"',
                               f'api_key = "{fake_secret(32, 23)}"')
        self.assertEqual([(f.rule, f.severity) for f in findings], [("secret.aws-key", Severity.LOW)])
        self.assertTrue(any("test/example" in n for n in notes))


class HelperTest(unittest.TestCase):
    def test_mask(self):
        self.assertEqual(mask("AKIA" + "1234567890ABCDEF"), "AKIA********")
        self.assertEqual(mask("hunter2"), "********")  # short: show nothing

    def test_is_placeholder(self):
        self.assertTrue(is_placeholder("your_token_here"))
        self.assertFalse(is_placeholder(fake_secret(30, 24)))


if __name__ == "__main__":
    unittest.main()

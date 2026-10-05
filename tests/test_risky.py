import unittest

from agentshield.checks.risky import check_risky
from agentshield.diff import parse_diff
from agentshield.findings import Severity

from .helpers import files_from, make_diff


def rules(*diffs):
    findings, _ = check_risky(files_from(*diffs))
    return sorted(f.rule for f in findings)


def one(path, *added, removed=()):
    """Rules triggered by a single-file diff, ignoring the 'no tests' summary."""
    return [r for r in rules(make_diff(path, list(added), list(removed))) if r != "risky.no-tests"]


class AuthTest(unittest.TestCase):
    def test_removed_guard(self):
        findings, _ = check_risky(files_from(make_diff(
            "app/views.py", ["def billing(request):"],
            removed=["@login_required", "def billing(request):"])))
        f = [f for f in findings if f.rule == "risky.auth-guard-removed"][0]
        self.assertEqual((f.severity, f.line), (Severity.MEDIUM, 1))

    def test_moved_guard_is_not_removed(self):
        self.assertEqual(one("app/views.py", "@login_required", "def billing(request):",
                             removed=["@login_required", "def billing(req):"]), [])

    def test_auth_file_touched(self):
        self.assertEqual(one("src/auth/session.ts", "const ttl = 3600;"), ["risky.auth-change"])
        self.assertEqual(one("app/login.py", "x = 1"), ["risky.auth-change"])

    def test_author_is_not_auth(self):
        self.assertEqual(one("blog/authors.py", "x = 1"), [])
        self.assertEqual(one("db/session.py", "x = 1"), [])
        self.assertEqual(one("docs/auth.md", "Login with SSO"), [])


class MigrationTest(unittest.TestCase):
    def test_drops_are_high(self):
        cases = [
            ("db/migrations/002.sql", "DROP TABLE users;"),
            ("db/migrations/003.sql", "alter table orders drop column notes;"),
            ("alembic/versions/ab12_cleanup.py", "    op.drop_column('users', 'email')"),
            ("shop/migrations/0007_remove.py", "        migrations.RemoveField(model_name='order', name='note'),"),
            ("db/migrate/2024_drop.rb", "    drop_table :legacy_users"),
            ("migrations/20240101_x.js", "  await knex.schema.dropTable('sessions');"),
        ]
        for path, line in cases:
            with self.subTest(path=path):
                findings, _ = check_risky(files_from(make_diff(path, [line])))
                self.assertEqual([(f.rule, f.severity) for f in findings],
                                 [("risky.destructive-migration", Severity.HIGH)])

    def test_downgrade_reversals_are_normal(self):
        alembic = ["def upgrade():", "    op.create_table('users')", "",
                   "def downgrade():", "    op.drop_table('users')"]
        self.assertEqual(one("alembic/versions/1_users.py", *alembic), [])
        knex = ["exports.up = k => k.schema.createTable('a');",
                "exports.down = k => k.schema.dropTable('a');"]
        self.assertEqual(one("migrations/1.js", *knex), [])
        self.assertEqual(one("migrations/0001_users.down.sql", "DROP TABLE users;"), [])

    def test_upgrade_after_downgrade_still_checked(self):
        lines = ["def downgrade():", "    pass", "def upgrade():", "    op.drop_table('x')"]
        self.assertEqual(one("alembic/versions/2.py", *lines), ["risky.destructive-migration"])

    def test_prose_and_helpers_are_not_migrations(self):
        self.assertEqual(one("utils/text.py", "# Truncate long names before saving",
                             "def drop_table(name): ...", "name = truncate(name, 20)"), [])


class TestChangesTest(unittest.TestCase):
    def test_deleted_test_file(self):
        diff = ("diff --git a/tests/test_pay.py b/tests/test_pay.py\ndeleted file mode 100644\n"
                "--- a/tests/test_pay.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-def test_x():\n-    pass\n")
        self.assertEqual(rules(diff), ["risky.test-deleted"])

    def test_removed_test_function(self):
        self.assertEqual(one("tests/test_pay.py", "def test_refund():",
                             removed=["def test_refund():", "def test_charge_declined():"]),
                         ["risky.test-deleted"])
        self.assertEqual(one("web/cart.test.ts", removed=["  it('rejects empty cart', () => {"]),
                         ["risky.test-deleted"])

    def test_renamed_test_body_change_is_fine(self):
        self.assertEqual(one("tests/test_pay.py", "def test_refund():", "    assert ok",
                             removed=["def test_refund():", "    assert True"]), [])

    def test_skipped_and_only(self):
        self.assertEqual(one("tests/test_a.py", "@pytest.mark.skip(reason='flaky')"), ["risky.test-skipped"])
        self.assertEqual(one("tests/test_a.py", "@unittest.skip('later')"), ["risky.test-skipped"])
        self.assertEqual(one("src/a.spec.ts", "  it.only('works', () => {"), ["risky.test-skipped"])
        self.assertEqual(one("pkg/a_test.go", "\tt.Skip(\"todo\")"), ["risky.test-skipped"])

    def test_conditional_skip_is_fine(self):
        self.assertEqual(one("tests/test_a.py", "@unittest.skipIf(sys.platform == 'win32', 'posix only')",
                             "@pytest.mark.skipif(not HAS_GPU, reason='gpu')"), [])

    def test_source_without_tests(self):
        code = [f"x{i} = {i}" for i in range(12)]
        self.assertEqual(rules(make_diff("app/core.py", code)), ["risky.no-tests"])
        # Same change with a test touched: fine.
        self.assertEqual(rules(make_diff("app/core.py", code),
                               make_diff("tests/test_core.py", ["def test_x(): pass"])), [])
        # Tiny change: fine.
        self.assertEqual(rules(make_diff("app/core.py", code[:3])), [])
        # Docs and config don't count as source.
        self.assertEqual(rules(make_diff("README.md", code), make_diff("conf.yml", code)), [])


class LineRuleTest(unittest.TestCase):
    def test_insecure_settings(self):
        lines = ["r = requests.get(url, verify=False)", "DEBUG = True",
                 "CORS_ALLOW_ALL_ORIGINS = True", "app.add_middleware(CORSMiddleware, allow_origins=['*'])",
                 "ALLOWED_HOSTS = ['*']", "@csrf_exempt", "ctx = ssl._create_unverified_context()",
                 "  rejectUnauthorized: false,", "app.use(cors());"]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(one("app/settings.py", line), ["risky.insecure-setting"])

    def test_dangerous_calls(self):
        lines = ["result = eval(user_input)", "exec(code)", "subprocess.run(cmd, shell=True)",
                 "os.system('rm -rf ' + path)", "obj = pickle.loads(data)", "cfg = yaml.load(f)",
                 "const f = new Function('a', body);", "<div dangerouslySetInnerHTML={{__html: x}} />",
                 "child_process.exec(`git ${args}`)"]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(one("app/run.py", line), ["risky.dangerous-call"])

    def test_safe_lookalikes(self):
        lines = ["model.eval()", "value = ast.literal_eval(s)", "cfg = yaml.load(f, Loader=yaml.SafeLoader)",
                 "cfg = yaml.safe_load(f)", "DEBUG = os.getenv('DEBUG') == '1'", "# never use eval(x) here",
                 "cursor.execute(sql, params)", "verify=True", "re.compile(p).exec(s)",
                 "transport = nodemailer.createTransport({ secure: false })"]
        self.assertEqual(one("app/run.py", *lines), [])

    def test_tests_and_docs_exempt(self):
        self.assertEqual(one("tests/test_api.py", "requests.get(u, verify=False)", "eval('1+1')"), [])
        self.assertEqual(one("docs/security.md", "Never call eval(input())."), [])


class DeletedFileTest(unittest.TestCase):
    def test_deleting_an_auth_file_needs_review(self):
        diff = ("diff --git a/app/auth.py b/app/auth.py\ndeleted file mode 100644\n"
                "--- a/app/auth.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x = 1\n")
        files = parse_diff(diff)
        self.assertTrue(files[0].is_deleted)
        self.assertEqual(check_risky(files)[0][0].rule, "risky.auth-change")


if __name__ == "__main__":
    unittest.main()

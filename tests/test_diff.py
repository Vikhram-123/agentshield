import unittest

from agentshield.diff import parse_diff

SAMPLE = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -10,4 +10,5 @@ def f():
     keep1
-    old
+    new1
+    new2
     keep2
\\ No newline at end of file
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1 +0,0 @@
-bye
diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+x = 1
+y = 2
"""


class ParseDiffTest(unittest.TestCase):
    def setUp(self):
        self.files = {f.path: f for f in parse_diff(SAMPLE)}

    def test_line_numbers_follow_hunk_header(self):
        added = self.files["a.py"].added
        self.assertEqual([(a.number, a.text) for a in added], [(11, "    new1"), (12, "    new2")])
        removed = self.files["a.py"].removed
        self.assertEqual([(r.number, r.text) for r in removed], [(11, "    old")])

    def test_deleted_and_new_files(self):
        self.assertTrue(self.files["gone.py"].is_deleted)
        self.assertTrue(self.files["new.py"].is_new)
        self.assertEqual([a.number for a in self.files["new.py"].added], [1, 2])

    def test_lines_that_look_like_headers_inside_hunk(self):
        diff = "diff --git a/s.sql b/s.sql\n--- a/s.sql\n+++ b/s.sql\n@@ -1 +1,2 @@\n x\n+--- comment\n"
        f = parse_diff(diff)[0]
        self.assertEqual(f.added[0].text, "--- comment")


if __name__ == "__main__":
    unittest.main()

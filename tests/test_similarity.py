import unittest

from agentshield.similarity import closest, edit_distance, normalize


class SimilarityTest(unittest.TestCase):
    def test_edit_distance(self):
        self.assertEqual(edit_distance("requests", "reqeusts"), 1)  # swap
        self.assertEqual(edit_distance("requests", "request"), 1)   # delete
        self.assertEqual(edit_distance("numpy", "numpi"), 1)        # substitute
        self.assertEqual(edit_distance("abc", "abc"), 0)

    def test_normalize(self):
        self.assertEqual(normalize("Flask_SQLAlchemy"), normalize("flask-sqlalchemy"))

    def test_closest(self):
        pop = {"requests", "numpy", "six"}
        self.assertEqual(closest("reqeusts", pop), ("requests", 1))
        self.assertIsNone(closest("requests", pop))  # exact match is not a typo
        self.assertIsNone(closest("sip", pop))       # too short to judge
        self.assertIsNone(closest("totally-different", pop))


if __name__ == "__main__":
    unittest.main()

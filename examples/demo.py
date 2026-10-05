"""A realistic "AI-written" pull request, scanned by AgentShield.

    python examples/demo.py            # live PyPI/npm lookups
    python examples/demo.py --offline  # no network

The PR ("Add Stripe billing webhook") has the mistakes AgentShield looks for:
a hallucinated dependency, a typo'd one, a hardcoded live key, TLS checks
turned off, a shell command built from input, a destructive migration, and a
test that was skipped instead of fixed.

The diff is generated at runtime so the fake key never sits in this repo as
a key-shaped string (see DECISIONS.md #16).
"""

from __future__ import annotations

import os
import random
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield import cli  # noqa: E402


def fake(n: int, seed: int) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789") for _ in range(n))


def demo_diff() -> str:
    key = "sk_" + "live_" + fake(24, 7)
    return f"""diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,4 @@
 flask==3.0.3
 stripe==10.1.0
+flask-stripe-webhooks==1.4.2
+reqeusts==2.32.0
diff --git a/app/billing.py b/app/billing.py
new file mode 100644
--- /dev/null
+++ b/app/billing.py
@@ -0,0 +1,18 @@
+import subprocess
+
+import requests
+import stripe
+from flask_stripe_webhooks import verify_event
+
+stripe.api_key = "{key}"
+
+
+def notify_accounting(invoice_id):
+    requests.post("https://accounting.internal/hook", json={{"id": invoice_id}}, verify=False)
+
+
+def export_invoice(invoice_id, fmt):
+    subprocess.run(f"invoice-export {{invoice_id}} --format {{fmt}}", shell=True)
+
+
+event = verify_event
diff --git a/db/migrations/0007_billing.sql b/db/migrations/0007_billing.sql
new file mode 100644
--- /dev/null
+++ b/db/migrations/0007_billing.sql
@@ -0,0 +1,2 @@
+ALTER TABLE users ADD COLUMN stripe_customer_id TEXT;
+ALTER TABLE users DROP COLUMN legacy_plan;
diff --git a/tests/test_billing.py b/tests/test_billing.py
--- a/tests/test_billing.py
+++ b/tests/test_billing.py
@@ -10,4 +10,5 @@ def test_charge():
     assert charge(100).ok

+@pytest.mark.skip(reason="flaky after webhook change")
 def test_refund():
     assert refund(100).ok
"""


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "ai-pr.diff")
        with open(path, "w") as fh:
            fh.write(demo_diff())
        return cli.main(["scan", "--diff", path, "--repo", tmp, *sys.argv[1:]])


if __name__ == "__main__":
    sys.exit(main())

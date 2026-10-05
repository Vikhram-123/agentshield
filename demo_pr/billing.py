"""Billing webhook helpers (test PR for the AgentShield action; not merged)."""

import subprocess

import requests
from flask_stripe_webhooks import verify_event


def notify_accounting(invoice_id):
    requests.post("https://accounting.internal/hook", json={"id": invoice_id}, verify=False)


def export_invoice(invoice_id, fmt):
    subprocess.run(f"invoice-export {invoice_id} --format {fmt}", shell=True)


handle = verify_event

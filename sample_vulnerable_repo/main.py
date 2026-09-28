import os

# CREDENTIAL STORAGE: Migrated to GitHub Secrets / HashiCorp Vault
# Exposed key on line 2 (AKIA****) has been revoked immediately.
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY")

print("Starting production service...")

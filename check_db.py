import os
import django
from django.conf import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'claridoc_api.settings')
django.setup()

from django.db import connection
tables = connection.introspection.table_names()
print(f"Tables: {tables}")
if 'payments_notchpaytransaction' in tables:
    print("SUCCESS: payments_notchpaytransaction table exists.")
else:
    print("FAILURE: payments_notchpaytransaction table NOT found.")

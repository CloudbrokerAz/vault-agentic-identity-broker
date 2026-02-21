"""
PostgreSQL Schema Validation Tests

Validates the SQL initialization scripts for correct schema,
table definitions, constraints, sample data, and security configuration.
"""

import os
import re
import unittest

SQL_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "postgres", "init")


class TestVaultUserSQL(unittest.TestCase):
    """Validate the Vault admin user creation script."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SQL_DIR, "00-vault-user.sql")) as f:
            cls.sql = f.read()

    def test_creates_vault_admin(self):
        self.assertIn("CREATE USER vault_admin", self.sql)

    def test_vault_admin_has_superuser(self):
        self.assertIn("SUPERUSER", self.sql)

    def test_vault_admin_has_createrole(self):
        self.assertIn("CREATEROLE", self.sql)

    def test_grants_privileges_on_appdb(self):
        self.assertIn("GRANT ALL PRIVILEGES ON DATABASE appdb TO vault_admin", self.sql)


class TestInitSQL(unittest.TestCase):
    """Validate the main initialization script."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SQL_DIR, "01-init.sql")) as f:
            cls.sql = f.read()

    # ─── Schema ──────────────────────────────────────────────────────

    def test_creates_app_schema(self):
        self.assertIn("CREATE SCHEMA IF NOT EXISTS app", self.sql)

    # ─── Tables ──────────────────────────────────────────────────────

    def test_creates_orders_table(self):
        self.assertIn("CREATE TABLE app.orders", self.sql)

    def test_creates_customers_table(self):
        self.assertIn("CREATE TABLE app.customers", self.sql)

    def test_creates_products_table(self):
        self.assertIn("CREATE TABLE app.products", self.sql)

    # ─── Orders Table Columns ────────────────────────────────────────

    def test_orders_has_id(self):
        self.assertIn("id SERIAL PRIMARY KEY", self.sql)

    def test_orders_has_customer_name(self):
        self.assertIn("customer_name VARCHAR(100) NOT NULL", self.sql)

    def test_orders_has_total_amount_computed(self):
        self.assertIn("GENERATED ALWAYS AS (quantity * unit_price) STORED", self.sql)

    def test_orders_has_status_constraint(self):
        self.assertIn("'pending'", self.sql)
        self.assertIn("'confirmed'", self.sql)
        self.assertIn("'shipped'", self.sql)
        self.assertIn("'delivered'", self.sql)
        self.assertIn("'cancelled'", self.sql)

    def test_orders_quantity_positive(self):
        self.assertIn("CHECK (quantity > 0)", self.sql)

    def test_orders_price_non_negative(self):
        self.assertIn("CHECK (unit_price >= 0)", self.sql)

    # ─── Customers Table ─────────────────────────────────────────────

    def test_customers_has_unique_email(self):
        self.assertIn("email VARCHAR(200) UNIQUE NOT NULL", self.sql)

    def test_customers_has_tier_constraint(self):
        self.assertIn("'standard'", self.sql)
        self.assertIn("'premium'", self.sql)
        self.assertIn("'enterprise'", self.sql)

    # ─── Products Table ──────────────────────────────────────────────

    def test_products_price_non_negative(self):
        self.assertIn("CHECK (price >= 0)", self.sql)

    # ─── Sample Data ─────────────────────────────────────────────────

    def test_inserts_customers(self):
        customer_count = self.sql.count("INSERT INTO app.customers")
        self.assertGreaterEqual(customer_count, 1)
        # Check specific customers exist
        self.assertIn("Acme Corp", self.sql)
        self.assertIn("Wayne Enterprises", self.sql)
        self.assertIn("Umbrella Corp", self.sql)

    def test_inserts_products(self):
        self.assertIn("INSERT INTO app.products", self.sql)
        self.assertIn("AI Processing Unit", self.sql)
        self.assertIn("Security Scanner", self.sql)

    def test_inserts_orders(self):
        self.assertIn("INSERT INTO app.orders", self.sql)
        # Should have a mix of statuses
        self.assertIn("'confirmed'", self.sql)
        self.assertIn("'shipped'", self.sql)
        self.assertIn("'delivered'", self.sql)
        self.assertIn("'cancelled'", self.sql)
        self.assertIn("'pending'", self.sql)

    def test_orders_have_regions(self):
        self.assertIn("North America", self.sql)
        self.assertIn("Europe", self.sql)
        self.assertIn("Asia Pacific", self.sql)

    # ─── View ────────────────────────────────────────────────────────

    def test_creates_order_summary_view(self):
        self.assertIn("CREATE VIEW app.order_summary", self.sql)

    def test_order_summary_has_value_tier(self):
        self.assertIn("high-value", self.sql)
        self.assertIn("medium-value", self.sql)
        self.assertIn("standard", self.sql)

    def test_order_summary_value_thresholds(self):
        """High-value >= 10000, medium-value >= 1000."""
        self.assertIn("10000", self.sql)
        self.assertIn("1000", self.sql)

    # ─── Permissions ─────────────────────────────────────────────────

    def test_grants_usage_on_app_schema(self):
        self.assertIn("GRANT USAGE ON SCHEMA app TO PUBLIC", self.sql)

    def test_grants_select_on_all_tables(self):
        self.assertIn("GRANT SELECT ON ALL TABLES IN SCHEMA app TO PUBLIC", self.sql)

    def test_default_privileges(self):
        self.assertIn("ALTER DEFAULT PRIVILEGES IN SCHEMA app", self.sql)

    def test_grants_select_on_view(self):
        self.assertIn("GRANT SELECT ON app.order_summary TO PUBLIC", self.sql)

    # ─── Audit ───────────────────────────────────────────────────────

    def test_enables_pgaudit(self):
        self.assertIn("CREATE EXTENSION IF NOT EXISTS pgaudit", self.sql)

    def test_configures_pgaudit_for_reads(self):
        self.assertIn("pgaudit.log = 'read'", self.sql)


class TestSQLOrdering(unittest.TestCase):
    """Validate that SQL files execute in the correct order."""

    def test_vault_user_runs_first(self):
        """00-vault-user.sql should come before 01-init.sql."""
        files = sorted(os.listdir(SQL_DIR))
        sql_files = [f for f in files if f.endswith(".sql")]
        self.assertTrue(len(sql_files) >= 2)
        self.assertTrue(sql_files[0].startswith("00"))
        self.assertTrue(sql_files[1].startswith("01"))


if __name__ == "__main__":
    unittest.main()

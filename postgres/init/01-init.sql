-- PostgreSQL initialization for the Identity Broker demo
-- Creates sample schema and data that the AI agent will query

-- Note: pgaudit is not available in postgres:alpine images.
-- Audit logging is handled via PostgreSQL's native log_statement=all setting
-- configured in the docker-compose command.

-- Create the application schema
CREATE SCHEMA IF NOT EXISTS app;

-- Orders table (sample data the AI agent will query)
CREATE TABLE app.orders (
    id SERIAL PRIMARY KEY,
    customer_name VARCHAR(100) NOT NULL,
    product VARCHAR(200) NOT NULL,
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    unit_price DECIMAL(10,2) NOT NULL CHECK (unit_price >= 0),
    total_amount DECIMAL(12,2) GENERATED ALWAYS AS (quantity * unit_price) STORED,
    order_date TIMESTAMP NOT NULL DEFAULT NOW(),
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'confirmed', 'shipped', 'delivered', 'cancelled')),
    region VARCHAR(50),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Customers table
CREATE TABLE app.customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(200) UNIQUE NOT NULL,
    tier VARCHAR(20) NOT NULL DEFAULT 'standard'
        CHECK (tier IN ('standard', 'premium', 'enterprise')),
    region VARCHAR(50),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Products table
CREATE TABLE app.products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    category VARCHAR(100),
    price DECIMAL(10,2) NOT NULL CHECK (price >= 0),
    stock_quantity INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Insert sample customers
INSERT INTO app.customers (name, email, tier, region) VALUES
    ('Acme Corp', 'orders@acme.com', 'enterprise', 'North America'),
    ('Globex Inc', 'purchasing@globex.com', 'premium', 'Europe'),
    ('Initech', 'bills@initech.com', 'standard', 'North America'),
    ('Umbrella Corp', 'supply@umbrella.com', 'enterprise', 'Asia Pacific'),
    ('Wayne Enterprises', 'procurement@wayne.com', 'enterprise', 'North America'),
    ('Stark Industries', 'orders@stark.com', 'premium', 'North America'),
    ('Oscorp', 'purchasing@oscorp.com', 'standard', 'Europe'),
    ('Cyberdyne Systems', 'supply@cyberdyne.com', 'premium', 'Asia Pacific');

-- Insert sample products
INSERT INTO app.products (name, category, price, stock_quantity) VALUES
    ('Widget Pro', 'Hardware', 49.99, 500),
    ('Data Analyzer Suite', 'Software', 299.99, 999),
    ('Cloud Connector', 'Infrastructure', 149.99, 200),
    ('Security Scanner', 'Security', 599.99, 100),
    ('AI Processing Unit', 'Hardware', 1299.99, 50),
    ('Network Monitor', 'Infrastructure', 199.99, 300),
    ('Compliance Toolkit', 'Security', 449.99, 150),
    ('Edge Compute Module', 'Hardware', 899.99, 75);

-- Insert sample orders (mix of recent and historical, various amounts)
INSERT INTO app.orders (customer_name, product, quantity, unit_price, order_date, status, region) VALUES
    -- Recent high-value orders (last month)
    ('Acme Corp', 'AI Processing Unit', 10, 1299.99, NOW() - INTERVAL '5 days', 'confirmed', 'North America'),
    ('Wayne Enterprises', 'Security Scanner', 25, 599.99, NOW() - INTERVAL '8 days', 'shipped', 'North America'),
    ('Umbrella Corp', 'Data Analyzer Suite', 50, 299.99, NOW() - INTERVAL '12 days', 'confirmed', 'Asia Pacific'),
    ('Stark Industries', 'Cloud Connector', 100, 149.99, NOW() - INTERVAL '15 days', 'delivered', 'North America'),
    ('Globex Inc', 'AI Processing Unit', 5, 1299.99, NOW() - INTERVAL '20 days', 'shipped', 'Europe'),
    ('Cyberdyne Systems', 'Edge Compute Module', 20, 899.99, NOW() - INTERVAL '25 days', 'confirmed', 'Asia Pacific'),

    -- Recent standard orders
    ('Initech', 'Widget Pro', 200, 49.99, NOW() - INTERVAL '3 days', 'pending', 'North America'),
    ('Oscorp', 'Network Monitor', 15, 199.99, NOW() - INTERVAL '7 days', 'confirmed', 'Europe'),
    ('Acme Corp', 'Compliance Toolkit', 10, 449.99, NOW() - INTERVAL '10 days', 'shipped', 'North America'),

    -- Older orders (2-3 months ago)
    ('Wayne Enterprises', 'AI Processing Unit', 3, 1299.99, NOW() - INTERVAL '45 days', 'delivered', 'North America'),
    ('Globex Inc', 'Widget Pro', 500, 49.99, NOW() - INTERVAL '60 days', 'delivered', 'Europe'),
    ('Umbrella Corp', 'Security Scanner', 8, 599.99, NOW() - INTERVAL '75 days', 'delivered', 'Asia Pacific'),
    ('Stark Industries', 'Data Analyzer Suite', 20, 299.99, NOW() - INTERVAL '90 days', 'delivered', 'North America'),

    -- Cancelled orders
    ('Initech', 'AI Processing Unit', 2, 1299.99, NOW() - INTERVAL '30 days', 'cancelled', 'North America'),
    ('Oscorp', 'Edge Compute Module', 5, 899.99, NOW() - INTERVAL '40 days', 'cancelled', 'Europe');

-- Grant SELECT on public schema and app schema to any Vault-created roles
-- (Vault creates roles dynamically, so we use ALTER DEFAULT PRIVILEGES)
GRANT USAGE ON SCHEMA app TO PUBLIC;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT ON TABLES TO PUBLIC;

-- Create a view for easy order analysis
CREATE VIEW app.order_summary AS
SELECT
    o.id,
    o.customer_name,
    o.product,
    o.quantity,
    o.unit_price,
    o.total_amount,
    o.order_date,
    o.status,
    o.region,
    CASE
        WHEN o.total_amount >= 10000 THEN 'high-value'
        WHEN o.total_amount >= 1000 THEN 'medium-value'
        ELSE 'standard'
    END AS value_tier
FROM app.orders o
ORDER BY o.order_date DESC;

GRANT SELECT ON app.order_summary TO PUBLIC;

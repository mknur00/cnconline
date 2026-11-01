-- CNC ONLINE production database schema v1
-- Run via a controlled migration, not automatically on every app start.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS staff_users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,
  full_name text,
  role text NOT NULL DEFAULT 'sales' CHECK (role IN ('super_admin','manager','sales','workshop')),
  password_hash text,
  is_active boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS staff_users_email_unique ON staff_users (lower(email));

CREATE TABLE IF NOT EXISTS customers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_type text NOT NULL DEFAULT 'individual' CHECK (customer_type IN ('individual','trade')),
  name text NOT NULL,
  company_name text,
  email text,
  phone text,
  address_line1 text,
  address_line2 text,
  city text,
  postcode text,
  notes text,
  created_by uuid REFERENCES staff_users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS quotes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  quote_number bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
  customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE RESTRICT,
  status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','sent','accepted','declined','expired','converted')),
  currency char(3) NOT NULL DEFAULT 'GBP',
  subtotal_pence bigint NOT NULL DEFAULT 0 CHECK (subtotal_pence >= 0),
  discount_pence bigint NOT NULL DEFAULT 0 CHECK (discount_pence >= 0),
  vat_pence bigint NOT NULL DEFAULT 0 CHECK (vat_pence >= 0),
  total_pence bigint NOT NULL DEFAULT 0 CHECK (total_pence >= 0),
  customer_notes text,
  internal_notes text,
  expires_at timestamptz,
  created_by uuid REFERENCES staff_users(id) ON DELETE SET NULL,
  updated_by uuid REFERENCES staff_users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS quotes_customer_idx ON quotes(customer_id);

CREATE TABLE IF NOT EXISTS quote_items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  quote_id uuid NOT NULL REFERENCES quotes(id) ON DELETE CASCADE,
  sort_order integer NOT NULL DEFAULT 0,
  description text NOT NULL,
  material_code text,
  quantity numeric(12,3) NOT NULL DEFAULT 1 CHECK (quantity > 0),
  unit text NOT NULL DEFAULT 'each',
  unit_price_pence bigint NOT NULL DEFAULT 0 CHECK (unit_price_pence >= 0),
  line_total_pence bigint NOT NULL DEFAULT 0 CHECK (line_total_pence >= 0),
  specifications jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  quote_id uuid UNIQUE REFERENCES quotes(id) ON DELETE RESTRICT,
  customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE RESTRICT,
  status text NOT NULL DEFAULT 'new' CHECK (status IN ('new','approved','in_production','ready','dispatched','completed','cancelled')),
  due_date date,
  assigned_to uuid REFERENCES staff_users(id) ON DELETE SET NULL,
  production_notes text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS file_attachments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id uuid REFERENCES customers(id) ON DELETE CASCADE,
  quote_id uuid REFERENCES quotes(id) ON DELETE CASCADE,
  job_id uuid REFERENCES jobs(id) ON DELETE CASCADE,
  original_filename text NOT NULL,
  mime_type text,
  byte_size bigint NOT NULL CHECK (byte_size >= 0),
  storage_key text NOT NULL,
  uploaded_by uuid REFERENCES staff_users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (num_nonnulls(customer_id,quote_id,job_id) >= 1)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  actor_id uuid REFERENCES staff_users(id) ON DELETE SET NULL,
  entity_type text NOT NULL,
  entity_id uuid,
  action text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_log_created_idx ON audit_log(created_at DESC);

-- The initial super admin must be provisioned by a secure invitation/setup
-- flow. Do not insert an active account without verified credentials.

-- Production parts attached to workshop jobs
CREATE TABLE IF NOT EXISTS job_parts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  sort_order integer NOT NULL DEFAULT 0,
  part_name text NOT NULL,
  material text NOT NULL,
  thickness_mm numeric(8,2) NOT NULL CHECK (thickness_mm > 0),
  length_mm numeric(10,2) NOT NULL CHECK (length_mm > 0),
  width_mm numeric(10,2) NOT NULL CHECK (width_mm > 0),
  quantity integer NOT NULL DEFAULT 1 CHECK (quantity > 0),
  grain_direction text NOT NULL DEFAULT 'none' CHECK (grain_direction IN ('none','length','width')),
  edge_top boolean NOT NULL DEFAULT false,
  edge_bottom boolean NOT NULL DEFAULT false,
  edge_left boolean NOT NULL DEFAULT false,
  edge_right boolean NOT NULL DEFAULT false,
  notes text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS job_parts_job_idx ON job_parts(job_id);

-- Editable costing rates; prices are integer pence to avoid floating point currency errors.
CREATE TABLE IF NOT EXISTS costing_settings (
  key text PRIMARY KEY,
  value_pence bigint NOT NULL CHECK (value_pence >= 0),
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO costing_settings(key,value_pence) VALUES
 ('edgebanding_per_metre',247),
 ('cutting_per_metre',0)
ON CONFLICT (key) DO NOTHING;
CREATE TABLE IF NOT EXISTS material_sheet_prices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  material_name text NOT NULL,
  thickness_mm numeric(8,2) NOT NULL CHECK (thickness_mm > 0),
  sheet_length_mm integer NOT NULL CHECK (sheet_length_mm > 0),
  sheet_width_mm integer NOT NULL CHECK (sheet_width_mm > 0),
  price_pence bigint NOT NULL CHECK (price_pence >= 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(material_name,thickness_mm)
);

ALTER TABLE material_sheet_prices ADD COLUMN IF NOT EXISTS supplier_cost_pence bigint;

-- Uploaded customer enquiry attachments, stored in PostgreSQL for reliable persistence.
CREATE TABLE IF NOT EXISTS enquiry_uploads (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 quote_id uuid NOT NULL REFERENCES quotes(id) ON DELETE CASCADE,
 original_filename text NOT NULL,
 mime_type text,
 byte_size integer NOT NULL CHECK (byte_size > 0 AND byte_size <= 5242880),
 file_data bytea NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS enquiry_uploads_quote_idx ON enquiry_uploads(quote_id);

-- Actual workshop costs are recorded against jobs, never customer quotations.
CREATE TABLE IF NOT EXISTS job_actual_costs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
 category text NOT NULL CHECK (category IN ('material','cutting','cnc','edgebanding','labour','waste','overhead','other')),
 description text NOT NULL CHECK (length(description) BETWEEN 1 AND 250),
 amount_pence bigint NOT NULL CHECK (amount_pence >= 0),
 created_by uuid REFERENCES staff_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS job_actual_costs_job_idx ON job_actual_costs(job_id);

-- Immutable correction history: costs are voided, never physically deleted.
ALTER TABLE job_actual_costs ADD COLUMN IF NOT EXISTS voided_at timestamptz;
ALTER TABLE job_actual_costs ADD COLUMN IF NOT EXISTS voided_by uuid REFERENCES staff_users(id) ON DELETE SET NULL;
ALTER TABLE job_actual_costs ADD COLUMN IF NOT EXISTS void_reason text;

-- Manager cost-completeness review, separate from the underlying ledger.
CREATE TABLE IF NOT EXISTS job_cost_reviews (
 job_id uuid PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
 material_checked boolean NOT NULL DEFAULT false,
 machining_checked boolean NOT NULL DEFAULT false,
 labour_checked boolean NOT NULL DEFAULT false,
 overhead_checked boolean NOT NULL DEFAULT false,
 reviewed_by uuid REFERENCES staff_users(id) ON DELETE SET NULL,
 reviewed_at timestamptz
);

-- Any new or corrected actual cost invalidates the previous managerial review.
-- A database trigger keeps this atomic even when costs are written outside the API.
CREATE OR REPLACE FUNCTION invalidate_job_cost_review() RETURNS trigger AS $$
BEGIN
  UPDATE job_cost_reviews
  SET material_checked=false, machining_checked=false, labour_checked=false,
      overhead_checked=false, reviewed_at=NULL, reviewed_by=NULL
  WHERE job_id=NEW.job_id;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS job_actual_cost_review_invalidate ON job_actual_costs;
CREATE TRIGGER job_actual_cost_review_invalidate
AFTER INSERT OR UPDATE OF voided_at ON job_actual_costs
FOR EACH ROW EXECUTE FUNCTION invalidate_job_cost_review();

-- Stage 5: durable commercial and production records. Existing orders remain untouched.
CREATE TABLE IF NOT EXISTS order_snapshots (
 job_id uuid PRIMARY KEY REFERENCES jobs(id) ON DELETE RESTRICT,
 quote_id uuid NOT NULL REFERENCES quotes(id) ON DELETE RESTRICT,
 quote_number text NOT NULL,
 quote_total_pence bigint NOT NULL CHECK (quote_total_pence >= 0),
 currency text NOT NULL DEFAULT 'GBP',
 items jsonb NOT NULL,
 captured_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS production_events (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
 stage text NOT NULL CHECK(stage IN ('new','cutting','cnc','edgebanding','quality_check','ready','dispatched','completed','on_hold')),
 notes text,
 actor_id uuid REFERENCES staff_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS production_events_job_idx ON production_events(job_id,created_at);
CREATE TABLE IF NOT EXISTS material_stock (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 material_name text NOT NULL,
 thickness_mm numeric(8,2) NOT NULL CHECK(thickness_mm>0),
 sheet_length_mm integer NOT NULL CHECK(sheet_length_mm>0),
 sheet_width_mm integer NOT NULL CHECK(sheet_width_mm>0),
 sheets_on_hand integer NOT NULL DEFAULT 0 CHECK(sheets_on_hand>=0),
 reorder_level integer NOT NULL DEFAULT 0 CHECK(reorder_level>=0),
 UNIQUE(material_name,thickness_mm,sheet_length_mm,sheet_width_mm)
);
CREATE TABLE IF NOT EXISTS stock_movements (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 stock_id uuid NOT NULL REFERENCES material_stock(id) ON DELETE RESTRICT,
 job_id uuid REFERENCES jobs(id) ON DELETE RESTRICT,
 quantity_change integer NOT NULL CHECK(quantity_change<>0),
 reason text NOT NULL,
 actor_id uuid REFERENCES staff_users(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS order_invoices (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 job_id uuid NOT NULL UNIQUE REFERENCES jobs(id) ON DELETE RESTRICT,
 invoice_number bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
 amount_pence bigint NOT NULL CHECK(amount_pence>=0),
 vat_pence bigint NOT NULL DEFAULT 0 CHECK(vat_pence>=0),
 status text NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','issued','paid','void')),
 issued_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS invoice_payments (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 invoice_id uuid NOT NULL REFERENCES order_invoices(id) ON DELETE RESTRICT,
 amount_pence bigint NOT NULL CHECK(amount_pence>0),
 reference text NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(),
 actor_id uuid REFERENCES staff_users(id) ON DELETE SET NULL
);

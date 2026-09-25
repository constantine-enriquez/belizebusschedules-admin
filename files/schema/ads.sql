-- D1 ads table for route-intent strip + card placements.
-- Run once in Cloudflare D1 if auto-ensure is disabled.

CREATE TABLE IF NOT EXISTS ads (
  id TEXT PRIMARY KEY,
  placement TEXT NOT NULL CHECK (placement IN ('strip', 'card')),
  origin TEXT NOT NULL,
  destination TEXT NOT NULL,
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('draft', 'active', 'paused')),
  category_kind TEXT NOT NULL CHECK (
    category_kind IN (
      'restaurant', 'hotel', 'shop', 'taxi',
      'tour', 'pharmacy', 'car_rental', 'other'
    )
  ),
  eyebrow TEXT,
  title TEXT NOT NULL,
  subtitle TEXT,
  body TEXT,
  support TEXT,
  discount_teaser TEXT,
  discount_code TEXT,
  discount_summary TEXT,
  discount_valid_until TEXT,
  ctas_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ads_route_placement
  ON ads(origin, destination, placement, status);

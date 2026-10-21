-- Passenger ad analytics (impressions, CTA clicks, discount interactions).
-- Public write: api.belizebusschedules.com POST /api/ads/event
-- Admin read: /api/admin/ads (stats attached)

CREATE TABLE IF NOT EXISTS ad_events (
  id TEXT PRIMARY KEY,
  ad_id TEXT NOT NULL,
  event TEXT NOT NULL CHECK (
    event IN ('impression', 'cta_click', 'discount_open', 'code_copy')
  ),
  placement TEXT CHECK (placement IN ('strip', 'card')),
  cta_type TEXT,
  origin TEXT,
  destination TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (ad_id) REFERENCES ads(id)
);

CREATE INDEX IF NOT EXISTS idx_ad_events_ad_created
  ON ad_events(ad_id, created_at);

CREATE INDEX IF NOT EXISTS idx_ad_events_event_created
  ON ad_events(event, created_at);

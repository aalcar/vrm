-- Read-through / write-through cache for assessment sections (spec §11), and the storage
-- for analyst-supplied manual entries (spec §7), which share this table by design.
CREATE TABLE IF NOT EXISTS assessments_cache (
    company    text        NOT NULL,
    service    text        NOT NULL,
    source     text        NOT NULL,
    section    jsonb       NOT NULL,
    fetched_at timestamptz NOT NULL DEFAULT now(),

    -- Manual rows are analyst data, not cache. They never expire, are never cleared by
    -- --no-cache, and are never overwritten automatically (spec §7).
    manual     boolean     NOT NULL DEFAULT false,

    PRIMARY KEY (company, service, source)
);

-- TTL sweeps only ever touch non-manual rows, so the index excludes manual entries.
CREATE INDEX IF NOT EXISTS assessments_cache_fetched_at_idx
    ON assessments_cache (fetched_at)
    WHERE NOT manual;

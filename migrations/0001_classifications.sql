CREATE TABLE classifications (
  id TEXT PRIMARY KEY,
  ray_id TEXT,
  created_at TEXT NOT NULL,
  completed_at TEXT,
  path TEXT NOT NULL,
  method TEXT NOT NULL,
  content_type TEXT NOT NULL,
  email_hmac TEXT,
  model TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'classified', 'skipped', 'error')),
  verdict TEXT CHECK (verdict IN ('likely_legitimate', 'suspicious', 'insufficient_evidence')),
  probabilities_json TEXT,
  confidence REAL CHECK (confidence >= 0 AND confidence <= 1),
  inference_ms INTEGER,
  input_tokens INTEGER,
  output_tokens INTEGER,
  action TEXT NOT NULL CHECK (action IN ('pending', 'forward')),
  error_code TEXT,
  CHECK ((status = 'pending' AND completed_at IS NULL AND action = 'pending') OR
         (status != 'pending' AND completed_at IS NOT NULL AND action = 'forward')),
  CHECK (status != 'classified' OR
         (verdict IS NOT NULL AND probabilities_json IS NOT NULL AND confidence IS NOT NULL))
);
CREATE INDEX classifications_created_at ON classifications(created_at);
CREATE INDEX classifications_ray_id ON classifications(ray_id);
CREATE INDEX classifications_email_hmac ON classifications(email_hmac);

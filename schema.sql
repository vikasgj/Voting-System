-- schema.sql
PRAGMA foreign_keys=OFF; -- Temporarily disable FKs for dropping
DROP TABLE IF EXISTS voters;
DROP TABLE IF EXISTS candidates;
DROP TABLE IF EXISTS votes;
DROP TABLE IF EXISTS admin;
PRAGMA foreign_keys=ON; -- Re-enable FKs

CREATE TABLE admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL -- Store HASHED password from env var
);

CREATE TABLE voters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT, -- Allow NULL for phone
    password TEXT NOT NULL, -- Store HASHED password
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
    -- Removed 'verified' column, successful insert implies verification via OTP now
);

CREATE TABLE candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE, -- Ensure candidate names are unique
    party TEXT NOT NULL,
    image_filename TEXT -- Store the filename of the uploaded image
);

CREATE TABLE votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voter_id INTEGER NOT NULL UNIQUE, -- Ensures one vote per voter_id (SQLite specific way)
    candidate_id INTEGER NOT NULL,
    vote_hash TEXT UNIQUE NOT NULL, -- Unique hash for each vote (for conceptual integrity)
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    FOREIGN KEY (voter_id) REFERENCES voters(id) ON DELETE CASCADE,
    FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE RESTRICT -- Don't allow deleting candidate if they have votes
);

-- Indexes for performance (optional but recommended)
CREATE INDEX idx_voters_email ON voters(email);
CREATE INDEX idx_votes_voter_id ON votes(voter_id);
CREATE INDEX idx_votes_candidate_id ON votes(candidate_id);

-- No blockchain table needed for this implementation
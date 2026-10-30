-- Members a member-list refresh dropped from a Circle. The host sends no
-- membership notification, so a former member's own listing requests
-- revalidate these Circles (a few per request, least recently checked first)
-- and a re-added member reappears without waiting for another reader.
-- This is never a read grant: listings still require a fresh can_read cache row.
CREATE TABLE IF NOT EXISTS circle_former_members (
    space_uri TEXT NOT NULL REFERENCES circles(space_uri) ON DELETE CASCADE,
    member_did TEXT NOT NULL,
    removed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_checked_at TIMESTAMPTZ,
    PRIMARY KEY (space_uri, member_did)
);

CREATE INDEX IF NOT EXISTS circle_former_members_member_idx
    ON circle_former_members (member_did, last_checked_at);

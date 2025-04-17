#!/bin/bash

# --- Locate Firefox default profile ---
PROFILE_PATH=$(find ~/.mozilla/firefox -maxdepth 1 -type d -name "*.default-esr" | head -n 1)
DB="$PROFILE_PATH/places.sqlite"

# --- Check for sqlite3 and DB file ---
command -v sqlite3 >/dev/null 2>&1 || { echo >&2 "sqlite3 is required but not installed. Aborting."; exit 1; }

if [[ ! -f "$DB" ]]; then
    echo "places.sqlite not found in profile. Aborting."
    exit 1
fi

# --- Ensure Firefox is closed ---
pkill firefox

# --- Get timestamp ---
NOW=$(date +%s000000)  # Firefox uses microseconds

# --- Get the Bookmarks Toolbar folder ID ---
TOOLBAR_ID=$(sqlite3 "$DB" "SELECT id FROM moz_bookmarks WHERE parent = 1 AND title = 'toolbar';")

if [[ -z "$TOOLBAR_ID" ]]; then
    echo "Failed to find Bookmarks Toolbar folder. Aborting."
    exit 1
fi

# --- Split comma-separated list into an array ---
IFS=',' read -ra URLS <<< "$1"

# --- Loop through each URL ---
for BOOKMARK_URL in "${URLS[@]}"; do
    BOOKMARK_URL=$(echo "$BOOKMARK_URL" | xargs)  # Trim whitespace
    if [[ -z "$BOOKMARK_URL" ]]; then
        continue
    fi

    # Generate reverse host
    REVERSE_HOST="$(echo "$BOOKMARK_URL" | sed -n 's|https\?://\([^/]*\).*|\1|p' | awk -F. '{for(i=NF;i>0;i--) printf("%s.",$i)}')"

    # Insert into moz_places
    sqlite3 "$DB" <<EOF
    INSERT OR IGNORE INTO moz_places (url, title, rev_host, hidden, typed, frecency)
    VALUES (
      '$BOOKMARK_URL',
      '',
      '$REVERSE_HOST',
      0,
      1,
      2000
    );
EOF

    # Get place_id
    PLACE_ID=$(sqlite3 "$DB" "SELECT id FROM moz_places WHERE url = '$BOOKMARK_URL';" | head -n 1)

    if [[ -z "$PLACE_ID" ]]; then
        echo "❌ Failed to get place_id for $BOOKMARK_URL"
        continue
    fi

    # Insert into moz_bookmarks
    sqlite3 "$DB" <<EOF
    INSERT INTO moz_bookmarks (type, fk, parent, position, title, dateAdded, lastModified)
    VALUES (
      1,
      $PLACE_ID,
      $TOOLBAR_ID,
      (SELECT IFNULL(MAX(position), -1) + 1 FROM moz_bookmarks WHERE parent = $TOOLBAR_ID),
      '',
      $NOW,
      $NOW
    );
EOF

    echo "✅ Added: $BOOKMARK_URL"
done

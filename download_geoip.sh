#!/bin/bash
# Download/update GeoLite2-City database
# Run this monthly to keep the database current

set -e

if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

if [ -z "$MAXMIND_LICENSE_KEY" ] || [ "$MAXMIND_LICENSE_KEY" = "your-license-key-here" ]; then
    echo "Error: MAXMIND_LICENSE_KEY not set in .env"
    exit 1
fi

echo "Downloading GeoLite2-City database..."
DOWNLOAD_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

curl -sSL "$DOWNLOAD_URL" -o geoip.tar.gz
tar -xzf geoip.tar.gz
mv GeoLite2-City_*/GeoLite2-City.mmdb .
rm -rf GeoLite2-City_* geoip.tar.gz

echo "GeoLite2-City.mmdb updated successfully"

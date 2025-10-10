#!/bin/sh
set -e

echo "🚀 Starting Nginx Config Generator..."

# Change to app directory
cd /app

# Check if settings.json exists
if [ ! -f "settings.json" ]; then
    echo "❌ Error: settings.json not found!"
    exit 1
fi

# Generate nginx configuration
echo "📝 Generating nginx configuration from settings.json..."
python3 generate_nginx_config.py --output /etc/nginx/nginx.conf

# Validate nginx configuration
echo "🔍 Validating nginx configuration..."
nginx -t

# Start nginx
echo "🌐 Starting nginx..."
exec nginx -g "daemon off;"

#!/usr/bin/env python3
"""
Nginx Proxy Configuration Generator
Converts settings.json to nginx-proxy.conf

Usage: python generate_nginx_config.py [--input settings.json] [--output nginx-proxy.conf]
"""

import json
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any

def load_settings(file_path: str) -> List[Dict[str, Any]]:
    """Load settings from JSON file."""
    try:
        with open(file_path, 'r') as f:
            settings = json.load(f)
        
        if not isinstance(settings, list):
            raise ValueError("Settings must be a list of domain configurations")
        
        return settings
    except FileNotFoundError:
        print(f"Error: Settings file '{file_path}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{file_path}': {e}")
        sys.exit(1)

def validate_setting(setting: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and normalize a single domain setting."""
    required_fields = ['domain', 'forwarding']
    
    for field in required_fields:
        if field not in setting:
            raise ValueError(f"Missing required field '{field}' in domain configuration")
    
    # Set defaults
    validated = {
        'domain': setting['domain'].strip(),
        'forwarding': setting['forwarding'].strip(),
        'ssl': setting.get('ssl', True),
        'ca_bundle': setting.get('ca-bundle', ''),
        'private_key': setting.get('private-key', ''),
        'rate_limit': setting.get('rate-limit', 100),
        'websocket': setting.get('websocket', True),
        'compression': setting.get('compression', True),
        'security_headers': setting.get('security-headers', True)
    }
    
    # Parse forwarding address
    if ':' in validated['forwarding']:
        host, port = validated['forwarding'].split(':', 1)
        validated['host'] = host
        validated['port'] = int(port)
    else:
        validated['host'] = validated['forwarding']
        validated['port'] = 80
    
    # Generate upstream name
    validated['upstream_name'] = validated['domain'].replace('.', '_').replace('-', '_') + '_backend'
    
    return validated

def generate_upstream_blocks(settings: List[Dict[str, Any]]) -> str:
    """Generate upstream server blocks."""
    upstreams = []
    
    for setting in settings:
        upstream = f"""    upstream {setting['upstream_name']} {{
        server {setting['host']}:{setting['port']};
        keepalive 32;
    }}"""
        upstreams.append(upstream)
    
    return '\n\n'.join(upstreams)

def generate_http_redirect_server(domains: List[str]) -> str:
    """Generate HTTP to HTTPS redirect server block."""
    domain_list = ' '.join(domains)
    
    return f"""    # HTTP to HTTPS redirect
    server {{
        listen 80;
        server_name {domain_list};
        
        # Allow Let's Encrypt ACME challenge
        location /.well-known/acme-challenge/ {{
            root /var/www/certbot;
        }}

        # Redirect all other traffic to HTTPS
        location / {{
            return 301 https://$server_name$request_uri;
        }}
    }}"""

def generate_ssl_server_block(setting: Dict[str, Any]) -> str:
    """Generate SSL server block for a domain."""
    domain = setting['domain']
    upstream_name = setting['upstream_name']
    
    # SSL certificate paths
    if setting['ca_bundle'] and setting['private_key']:
        ssl_cert = f"/etc/nginx/ssl/{setting['ca_bundle']}"
        ssl_key = f"/etc/nginx/ssl/{setting['private_key']}"
    else:
        # Default Let's Encrypt style paths
        ssl_cert = f"/etc/nginx/ssl/{domain}/fullchain.pem"
        ssl_key = f"/etc/nginx/ssl/{domain}/privkey.pem"
    
    # Security headers
    security_headers = ""
    if setting['security_headers']:
        security_headers = '''
        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "no-referrer-when-downgrade" always;
        add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;'''
    
    # WebSocket support
    websocket_headers = ""
    if setting['websocket']:
        websocket_headers = '''
            # WebSocket support
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";'''
    
    # Rate limiting
    rate_limit = ""
    if setting['rate_limit'] > 0:
        rate_limit = f'''
        # API endpoints with rate limiting
        location /api/ {{
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://{upstream_name};
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }}'''
    
    server_block = f"""    # {domain} - Forward to {setting['host']}:{setting['port']}
    server {{
        listen 443 ssl http2;
        server_name {domain};

        ssl_certificate {ssl_cert};
        ssl_certificate_key {ssl_key};{security_headers}

        # Main application
        location / {{
            proxy_pass http://{upstream_name};
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Port $server_port;{websocket_headers}
            
            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }}{rate_limit}
    }}"""
    
    return server_block

def generate_nginx_config(settings: List[Dict[str, Any]]) -> str:
    """Generate complete nginx configuration."""
    
    # Extract domains for HTTP redirect
    ssl_domains = [s['domain'] for s in settings if s['ssl']]
    
    # Check if compression is enabled for any domain
    compression_enabled = any(s['compression'] for s in settings)
    
    # Gzip configuration
    gzip_config = ""
    if compression_enabled:
        gzip_config = """
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;"""
    
    # Rate limiting zones
    rate_limit_zones = ""
    if any(s['rate_limit'] > 0 for s in settings):
        rate_limit_zones = """
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;"""
    
    # Generate upstream blocks
    upstream_blocks = generate_upstream_blocks(settings)
    
    # Generate HTTP redirect server
    http_redirect = ""
    if ssl_domains:
        http_redirect = generate_http_redirect_server(ssl_domains)
    
    # Generate SSL server blocks
    ssl_servers = []
    for setting in settings:
        if setting['ssl']:
            ssl_servers.append(generate_ssl_server_block(setting))
    
    # Complete configuration
    config = f"""events {{
    worker_connections 1024;
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    # Basic settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;{gzip_config}{rate_limit_zones}

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Upstream servers
{upstream_blocks}

{http_redirect}

{chr(10).join(ssl_servers)}
}}"""
    
    return config

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Generate nginx proxy configuration from settings.json')
    parser.add_argument('--input', '-i', default='settings.json', help='Input settings file (default: settings.json)')
    parser.add_argument('--output', '-o', default='nginx-proxy.conf', help='Output nginx config file (default: nginx-proxy.conf)')
    parser.add_argument('--dry-run', action='store_true', help='Print configuration to stdout instead of writing to file')
    
    args = parser.parse_args()
    
    # Load and validate settings
    settings_data = load_settings(args.input)
    
    try:
        validated_settings = [validate_setting(setting) for setting in settings_data]
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Generate configuration
    nginx_config = generate_nginx_config(validated_settings)
    
    if args.dry_run:
        print(nginx_config)
    else:
        # Write to file
        try:
            with open(args.output, 'w') as f:
                f.write(nginx_config)
            print(f"✅ Nginx configuration generated successfully: {args.output}")
            print(f"📁 Configured {len(validated_settings)} domain(s):")
            for setting in validated_settings:
                ssl_status = "🔒 HTTPS" if setting['ssl'] else "🔓 HTTP"
                print(f"   - {setting['domain']} → {setting['host']}:{setting['port']} ({ssl_status})")
        except IOError as e:
            print(f"Error writing to '{args.output}': {e}")
            sys.exit(1)

if __name__ == '__main__':
    main()

# Nginx Configuration Generator

Convert your `settings.json` to a complete `nginx-proxy.conf` file with either Python or JavaScript.

## 🚀 Quick Start

### Using Python
```bash
# Generate nginx-proxy.conf from settings.json
python3 generate_nginx_config.py

# Custom input/output files
python3 generate_nginx_config.py --input my-settings.json --output my-nginx.conf

# Preview without writing to file
python3 generate_nginx_config.py --dry-run
```

### Using Node.js/JavaScript
```bash
# Generate nginx-proxy.conf from settings.json
node generate_nginx_config.js

# Custom input/output files
node generate_nginx_config.js --input my-settings.json --output my-nginx.conf

# Preview without writing to file
node generate_nginx_config.js --dry-run
```

## ⚙️ Settings.json Format

```json
[
    {
        "domain": "example.com",
        "forwarding": "127.0.0.1:3003",
        "ssl": true,
        "ca-bundle": "cert/example.com/ca-bundle.txt",
        "private-key": "cert/example.com/private-key.txt"
    },
    {
        "domain": "api.example.com",
        "forwarding": "192.168.1.100:8000",
        "ssl": true,
        "rate-limit": {
            "/": 100,
            "/api": 10,
            "/upload": 2
        },
        "websocket": false
    },
    {
        "domain": "dev.example.com",
        "forwarding": "host.docker.internal:50030",
        "ssl": true,
        "http": true
    }
]
```

## 📋 Configuration Options

### Required Fields
- **`domain`**: The domain name to serve (e.g., "example.com")
- **`forwarding`**: Backend server address and port (e.g., "127.0.0.1:3000")

### Optional Fields
- **`ssl`**: Enable HTTPS (default: `true`)
- **`ca-bundle`**: Path to SSL certificate file (relative to `/etc/nginx/ssl/`)
- **`private-key`**: Path to SSL private key file (relative to `/etc/nginx/ssl/`)
- **`http`**: Allow HTTP forwarding instead of redirecting to HTTPS (default: `false`)
- **`rate-limit`**: Rate limiting per minute - can be a number (applies to all paths) or object with path-specific limits (default: no limits)
- **`websocket`**: Enable WebSocket support (default: `true`)
- **`compression`**: Enable gzip compression (default: `true`)
- **`security-headers`**: Enable security headers (default: `true`)

## 🔒 SSL Certificate Handling

### Option 1: Specify Custom Paths
```json
{
    "domain": "example.com",
    "forwarding": "127.0.0.1:3000",
    "ca-bundle": "example.com/fullchain.pem",
    "private-key": "example.com/privkey.pem"
}
```

### Option 2: Use Default Let's Encrypt Structure
```json
{
    "domain": "example.com",
    "forwarding": "127.0.0.1:3000",
    "ssl": true
}
```
This will use:
- Certificate: `/etc/nginx/ssl/example.com/fullchain.pem`
- Private Key: `/etc/nginx/ssl/example.com/privkey.pem`

## 🔀 HTTP Forwarding vs HTTPS Redirect

### Option 1: HTTP Forwarding (http: true)
```json
{
    "domain": "dev.example.com",
    "forwarding": "host.docker.internal:50030",
    "ssl": true,
    "http": true
}
```
- HTTP requests to `http://dev.example.com/test` are forwarded to `http://host.docker.internal:50030/test`
- HTTPS requests to `https://dev.example.com/test` are forwarded to `http://host.docker.internal:50030/test`
- Useful for development environments or when backend doesn't support HTTPS

### Option 2: HTTPS Redirect (http: false, default)
```json
{
    "domain": "example.com",
    "forwarding": "127.0.0.1:3000",
    "ssl": true
}
```
- HTTP requests to `http://example.com/test` are redirected to `https://example.com/test`
- Only HTTPS requests reach the backend
- Recommended for production environments

## 🚦 Rate Limiting Configuration

### Option 1: Simple Rate Limiting (Legacy)
```json
{
    "domain": "api.example.com",
    "forwarding": "127.0.0.1:8000",
    "rate-limit": 100
}
```
- Applies 100 requests/minute limit to all paths

### Option 2: Path-Specific Rate Limiting
```json
{
    "domain": "api.example.com",
    "forwarding": "127.0.0.1:8000",
    "rate-limit": {
        "/": 200,
        "/api": 50,
        "/api/upload": 5,
        "/test/*/endpoint": 10
    }
}
```
- **`"/"`**: 200 requests/minute for root and unmatched paths
- **`"/api"`**: 50 requests/minute for API endpoints
- **`"/api/upload"`**: 5 requests/minute for upload endpoint (more specific, takes precedence)
- **`"/test/*/endpoint"`**: 10 requests/minute for wildcard pattern (matches `/test/abc/endpoint`, `/test/123/endpoint`, etc.)

### Rate Limiting Features
✅ **Path specificity**: More specific paths take precedence over general ones
✅ **Wildcard support**: Use `*` for pattern matching
✅ **Burst handling**: Includes burst=5 nodelay for smooth traffic handling
✅ **Per-domain zones**: Each domain gets separate rate limiting zones
✅ **Backward compatibility**: Number format still works as before

## 🎯 Generated Features

The scripts automatically generate:

✅ **HTTP to HTTPS redirects**
✅ **SSL/TLS configuration** with modern cipher suites
✅ **Security headers** (XSS, CSRF, etc.)
✅ **Rate limiting** for API endpoints
✅ **WebSocket support** for real-time apps
✅ **Gzip compression** for better performance
✅ **Proper proxy headers** for backend services
✅ **Connection timeouts** and keep-alive settings

## 📁 Example Settings for Multiple Domains

```json
[
    {
        "domain": "website.com",
        "forwarding": "127.0.0.1:3000",
        "ssl": true
    },
    {
        "domain": "api.website.com",
        "forwarding": "127.0.0.1:8000",
        "ssl": true,
        "rate-limit": {
            "/": 300,
            "/api/v1": 100,
            "/api/v1/upload": 10
        },
        "websocket": false
    },
    {
        "domain": "admin.website.com",
        "forwarding": "127.0.0.1:9000",
        "ssl": true,
        "rate-limit": 50,
        "security-headers": true
    },
    {
        "domain": "legacy.website.com",
        "forwarding": "192.168.1.50:80",
        "ssl": false,
        "compression": false
    },
    {
        "domain": "dev.website.com",
        "forwarding": "host.docker.internal:3001",
        "ssl": true,
        "http": true,
        "security-headers": false
    }
]
```

## 🔧 Command Line Options

| Option | Description |
|--------|-------------|
| `--input`, `-i` | Input settings JSON file (default: `settings.json`) |
| `--output`, `-o` | Output nginx config file (default: `nginx-proxy.conf`) |
| `--dry-run` | Print config to stdout instead of writing to file |
| `--help`, `-h` | Show help message |

## 🚀 Integration with Docker

After generating your config:

1. **Update your nginx-proxy.conf**:
   ```bash
   python3 generate_nginx_config.py
   ```

2. **Restart nginx container**:
   ```bash
   docker-compose restart proxy-nginx
   ```

3. **Check nginx syntax**:
   ```bash
   docker-compose exec proxy-nginx nginx -t
   ```

## 🛠️ Advanced Usage

### Environment-Specific Configs
```bash
# Development
python3 generate_nginx_config.py --input settings-dev.json --output nginx-dev.conf

# Production
python3 generate_nginx_config.py --input settings-prod.json --output nginx-prod.conf

# Staging
python3 generate_nginx_config.py --input settings-staging.json --output nginx-staging.conf
```

### Automated Deployment
```bash
#!/bin/bash
# deploy.sh
python3 generate_nginx_config.py --input production-settings.json
docker-compose exec proxy-nginx nginx -t && docker-compose restart proxy-nginx
```

## 📝 Notes

- The scripts validate your settings.json before generating the config
- SSL certificates must be placed in the correct directory structure
- Rate limiting is applied to `/api/` endpoints by default
- WebSocket connections are supported automatically
- All generated configs include modern security best practices

## 🐛 Troubleshooting

### Common Issues

1. **"Settings file not found"**
   - Ensure `settings.json` exists in the current directory
   - Use `--input` to specify a different file

2. **"Invalid JSON"**
   - Validate your JSON syntax using an online JSON validator
   - Check for trailing commas or missing quotes

3. **"Missing required field"**
   - Ensure each domain has both `domain` and `forwarding` fields
   - Check spelling and format of required fields

### Debug Your Config
```bash
# Test generated config syntax
docker-compose exec proxy-nginx nginx -t

# View generated upstream servers
grep -A5 "upstream" nginx-proxy.conf

# Check SSL certificate paths
grep "ssl_certificate" nginx-proxy.conf
```

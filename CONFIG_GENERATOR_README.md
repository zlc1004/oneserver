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
        "rate-limit": 200,
        "websocket": false
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
- **`rate-limit`**: API rate limiting per minute (default: `100`, set to `0` to disable)
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
        "rate-limit": 500,
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

#!/usr/bin/env node
/**
 * Nginx Proxy Configuration Generator
 * Converts settings.json to nginx-proxy.conf
 *
 * Usage: node generate_nginx_config.js [--input settings.json] [--output nginx-proxy.conf]
 */

const fs = require('fs');
const path = require('path');

class NginxConfigGenerator {
    constructor() {
        this.settings = [];
    }

    loadSettings(filePath) {
        try {
            const data = fs.readFileSync(filePath, 'utf8');
            const settings = JSON.parse(data);

            if (!Array.isArray(settings)) {
                throw new Error('Settings must be a list of domain configurations');
            }

            return settings;
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.error(`Error: Settings file '${filePath}' not found`);
            } else if (error instanceof SyntaxError) {
                console.error(`Error: Invalid JSON in '${filePath}': ${error.message}`);
            } else {
                console.error(`Error: ${error.message}`);
            }
            process.exit(1);
        }
    }

    validateSetting(setting) {
        const requiredFields = ['domain', 'forwarding'];

        for (const field of requiredFields) {
            if (!(field in setting)) {
                throw new Error(`Missing required field '${field}' in domain configuration`);
            }
        }

        // Set defaults and normalize
        const validated = {
            domain: setting.domain.trim(),
            forwarding: setting.forwarding.trim(),
            ssl: setting.ssl !== undefined ? setting.ssl : true,
            ca_bundle: setting['ca-bundle'] || '',
            private_key: setting['private-key'] || '',
            rate_limit: setting['rate-limit'] || 100,
            websocket: setting.websocket !== undefined ? setting.websocket : true,
            compression: setting.compression !== undefined ? setting.compression : true,
            security_headers: setting['security-headers'] !== undefined ? setting['security-headers'] : true
        };

        // Parse forwarding address
        if (validated.forwarding.includes(':')) {
            const [host, port] = validated.forwarding.split(':');
            validated.host = host;
            validated.port = parseInt(port, 10);
        } else {
            validated.host = validated.forwarding;
            validated.port = 80;
        }

        // Generate upstream name
        validated.upstream_name = validated.domain.replace(/\./g, '_').replace(/-/g, '_') + '_backend';

        return validated;
    }

    generateUpstreamBlocks(settings) {
        const upstreams = settings.map(setting =>
            `    upstream ${setting.upstream_name} {\n` +
            `        server ${setting.host}:${setting.port};\n` +
            `        keepalive 32;\n` +
            `    }`
        );

        return upstreams.join('\n\n');
    }

    generateHttpRedirectServer(domains) {
        const domainList = domains.join(' ');

        return `    # HTTP to HTTPS redirect
    server {
        listen 80;
        server_name ${domainList};

        # Allow Let's Encrypt ACME challenge
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }

        # Redirect all other traffic to HTTPS
        location / {
            return 301 https://$server_name$request_uri;
        }
    }`;
    }

    generateSslServerBlock(setting) {
        const { domain, upstream_name, host, port } = setting;

        // SSL certificate paths
        let ssl_cert, ssl_key;
        if (setting.ca_bundle && setting.private_key) {
            ssl_cert = `/etc/nginx/ssl/${setting.ca_bundle}`;
            ssl_key = `/etc/nginx/ssl/${setting.private_key}`;
        } else {
            // Default Let's Encrypt style paths
            ssl_cert = `/etc/nginx/ssl/${domain}/fullchain.pem`;
            ssl_key = `/etc/nginx/ssl/${domain}/privkey.pem`;
        }

        // Security headers
        const securityHeaders = setting.security_headers ? `
        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "no-referrer-when-downgrade" always;
        add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;` : '';

        // WebSocket support
        const websocketHeaders = setting.websocket ? `
            # WebSocket support
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";` : '';

        // Rate limiting
        const rateLimit = setting.rate_limit > 0 ? `
        # API endpoints with rate limiting
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://${upstream_name};
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }` : '';

        return `    # ${domain} - Forward to ${host}:${port}
    server {
        listen 443 ssl;
        http2 on;
        server_name ${domain};

        ssl_certificate ${ssl_cert};
        ssl_certificate_key ${ssl_key};${securityHeaders}

        # Main application
        location / {
            proxy_pass http://${upstream_name};
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Port $server_port;${websocketHeaders}

            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }${rateLimit}
    }`;
    }

    generateNginxConfig(settings) {
        // Extract domains for HTTP redirect
        const sslDomains = settings.filter(s => s.ssl).map(s => s.domain);

        // Check if compression is enabled for any domain
        const compressionEnabled = settings.some(s => s.compression);

        // Gzip configuration
        const gzipConfig = compressionEnabled ? `
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
        image/svg+xml;` : '';

        // Rate limiting zones
        const rateLimitZones = settings.some(s => s.rate_limit > 0) ? `
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;` : '';

        // Generate upstream blocks
        const upstreamBlocks = this.generateUpstreamBlocks(settings);

        // Generate HTTP redirect server
        const httpRedirect = sslDomains.length > 0 ? this.generateHttpRedirectServer(sslDomains) : '';

        // Generate SSL server blocks
        const sslServers = settings
            .filter(setting => setting.ssl)
            .map(setting => this.generateSslServerBlock(setting))
            .join('\n\n');

        // Complete configuration
        return `events {
    worker_connections 1024;
}

http {
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
    types_hash_max_size 2048;${gzipConfig}${rateLimitZones}

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Upstream servers
${upstreamBlocks}

${httpRedirect}

${sslServers}
}`;
    }

    run() {
        // Parse command line arguments
        const args = process.argv.slice(2);
        let inputFile = 'settings.json';
        let outputFile = 'nginx-proxy.conf';
        let dryRun = false;

        for (let i = 0; i < args.length; i++) {
            switch (args[i]) {
                case '--input':
                case '-i':
                    inputFile = args[++i];
                    break;
                case '--output':
                case '-o':
                    outputFile = args[++i];
                    break;
                case '--dry-run':
                    dryRun = true;
                    break;
                case '--help':
                case '-h':
                    console.log('Usage: node generate_nginx_config.js [options]');
                    console.log('Options:');
                    console.log('  --input, -i <file>   Input settings file (default: settings.json)');
                    console.log('  --output, -o <file>  Output nginx config file (default: nginx-proxy.conf)');
                    console.log('  --dry-run           Print configuration to stdout instead of writing to file');
                    console.log('  --help, -h          Show this help message');
                    process.exit(0);
            }
        }

        // Load and validate settings
        const settingsData = this.loadSettings(inputFile);

        try {
            const validatedSettings = settingsData.map(setting => this.validateSetting(setting));

            // Generate configuration
            const nginxConfig = this.generateNginxConfig(validatedSettings);

            if (dryRun) {
                console.log(nginxConfig);
            } else {
                // Write to file
                try {
                    fs.writeFileSync(outputFile, nginxConfig);
                    console.log(`✅ Nginx configuration generated successfully: ${outputFile}`);
                    console.log(`📁 Configured ${validatedSettings.length} domain(s):`);
                    validatedSettings.forEach(setting => {
                        const sslStatus = setting.ssl ? "🔒 HTTPS" : "🔓 HTTP";
                        console.log(`   - ${setting.domain} → ${setting.host}:${setting.port} (${sslStatus})`);
                    });
                } catch (error) {
                    console.error(`Error writing to '${outputFile}': ${error.message}`);
                    process.exit(1);
                }
            }
        } catch (error) {
            console.error(`Error: ${error.message}`);
            process.exit(1);
        }
    }
}

// Run the generator
const generator = new NginxConfigGenerator();
generator.run();

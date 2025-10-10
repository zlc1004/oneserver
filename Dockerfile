FROM nginx:alpine

# Install python/pip
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python
# RUN mv /usr/lib/python3.11/EXTERNALLY-MANAGED /usr/lib/python3.11/EXTERNALLY-MANAGED.old
# RUN python3 -m ensurepip
# RUN pip3 install --no-cache --upgrade pip setuptools

# Create necessary directories
RUN mkdir -p /etc/nginx/ssl /var/www/certbot /app

# Copy application files
COPY generate_nginx_config.py /app/
COPY settings.json /app/
COPY entrypoint.sh /app/

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Expose ports
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

FROM nginx:alpine

# Install python/pip
ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python
# Create necessary directories
RUN mkdir /app
# Copy application files
COPY generate_nginx_config.py /app/
COPY settings.json /app/

RUN ["python3", "/app/generate_nginx_config.py", "--input", "/app/settings.json", "--output", "/etc/nginx/nginx.conf"]
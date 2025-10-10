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
COPY entrypoint.sh /app/

RUN ["chmod", "+x", "/app/entrypoint.sh"]
RUN ["cp", "/app/entrypoint.sh", "/docker-entrypoint.sh"]
RUN ["chmod", "+x", "/docker-entrypoint.sh"]

# Set entrypoint
ENTRYPOINT ["/docker-entrypoint.sh"]

STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "daemon off;"]

ENV NJS_VERSION=0.9.0
ENV NJS_RELEASE=1
RUN /bin/sh -c set -x && apkArch="$(cat /etc/apk/arch)" && nginxPackages=" nginx=${NGINX_VERSION}-r${PKG_RELEASE} nginx-module-xslt=${NGINX_VERSION}-r${DYNPKG_RELEASE} nginx-module-geoip=${NGINX_VERSION}-r${DYNPKG_RELEASE} nginx-module-image-filter=${NGINX_VERSION}-r${DYNPKG_RELEASE} nginx-module-njs=${NGINX_VERSION}.${NJS_VERSION}-r${NJS_RELEASE} " && apk add --no-cache --virtual .checksum-deps openssl && case "$apkArch" in x86_64|aarch64) apk add -X "https://nginx.org/packages/mainline/alpine/v$(egrep -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" --no-cache $nginxPackages ;; *) set -x && tempDir="$(mktemp -d)" && chown nobody:nobody $tempDir && apk add --no-cache --virtual .build-deps gcc libc-dev make openssl-dev pcre2-dev zlib-dev linux-headers libxslt-dev gd-dev geoip-dev libedit-dev bash alpine-sdk findutils curl && su nobody -s /bin/sh -c " export HOME=${tempDir} && cd ${tempDir} && curl -f -L -O https://github.com/nginx/pkg-oss/archive/${NGINX_VERSION}-${PKG_RELEASE}.tar.gz && PKGOSSCHECKSUM=\"400593da45fc0195a01138c0c23a06059da1c6a2e26959f2c4c95fbaf63436ff211665ef01392d2b775a0133d5b57680dabe51b840a55f82e89621e84cf651d1 *${NGINX_VERSION}-${PKG_RELEASE}.tar.gz\" && if [ \"\$(openssl sha512 -r ${NGINX_VERSION}-${PKG_RELEASE}.tar.gz)\" = \"\$PKGOSSCHECKSUM\" ]; then echo \"pkg-oss tarball checksum verification succeeded!\"; else echo \"pkg-oss tarball checksum verification failed!\"; exit 1; fi && tar xzvf ${NGINX_VERSION}-${PKG_RELEASE}.tar.gz && cd pkg-oss-${NGINX_VERSION}-${PKG_RELEASE} && cd alpine && make module-geoip module-image-filter module-njs module-xslt && apk index --allow-untrusted -o ${tempDir}/packages/alpine/${apkArch}/APKINDEX.tar.gz ${tempDir}/packages/alpine/${apkArch}/*.apk && abuild-sign -k ${tempDir}/.abuild/abuild-key.rsa ${tempDir}/packages/alpine/${apkArch}/APKINDEX.tar.gz " && cp ${tempDir}/.abuild/abuild-key.rsa.pub /etc/apk/keys/ && apk del --no-network .build-deps && apk add -X ${tempDir}/packages/alpine/ --no-cache $nginxPackages ;; esac && apk del --no-network .checksum-deps && if [ -n "$tempDir" ]; then rm -rf "$tempDir"; fi && if [ -f "/etc/apk/keys/abuild-key.rsa.pub" ]; then rm -f /etc/apk/keys/abuild-key.rsa.pub; fi && apk add --no-cache curl ca-certificates # buildkit
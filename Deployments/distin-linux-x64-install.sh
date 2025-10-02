﻿#!/bin/sh
set -eu

# Usage: ./distin-linux-x64-install.sh <webserver:apache2|nginx> <domain> <letsencrypt-email>

# root-check (ohne EUID: bashism)
if [ "$(id -u)" -ne 0 ]; then
  echo "please execute as root (sudo)."
  exit 1
fi

WEBSERVER="${1:-}"
DOMAIN="${2:-}"
EMAIL="${3:-}"
PORT="5000"

if [ -z "$WEBSERVER" ] || [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
  echo "error: missing parameters."
  echo "usage: $0 <webserver:apache2|nginx> <domain> <letsencrypt-email>"
  exit 1
fi

case "$WEBSERVER" in
  apache2) echo "installing DistIN instance with apache2:" ;;
  nginx)   echo "installing DistIN instance with nginx:" ;;
  *) echo "error: invalid web server parameter"; exit 1 ;;
esac

echo "DistIN instance installation started..."

# download & extract tar.gz
echo "downloading distin-linux-x64.tar.gz"
wget -O /srv/distin-linux-x64.tar.gz \
  "https://raw.githubusercontent.com/LIONS-DLT/DistIN-dotnet/main/Deployments/distin-linux-x64.tar.gz"

echo "preparing target dir /srv/distin ..."
mkdir -p /srv/distin
echo "extracting to /srv/distin ..."
tar -xvzf /srv/distin-linux-x64.tar.gz -C /srv/distin
rm -f /srv/distin-linux-x64.tar.gz || true

echo "configuring user and rights..."
# idempotent user creation (system user, no login)
if id -u distinuser >/dev/null 2>&1; then
  echo "user 'distinuser' already exists."
else
  # Fallback: create normal user if useradd not present
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /srv/distin --shell /usr/sbin/nologin distinuser
  else
    adduser --disabled-login --gecos "" distinuser || true
  fi
fi
chown -R distinuser:distinuser /srv/distin
chmod -R 700 /srv/distin

# make app executable if present
if [ -f /srv/distin/distin/DistIN.Application ]; then
  chmod +x /srv/distin/distin/DistIN.Application
fi

echo "configuring service..."
cat <<EOF >/etc/systemd/system/distin.service
[Unit]
Description=DistIN.Application
After=network.target

[Service]
Type=simple
User=distinuser
WorkingDirectory=/srv/distin/distin
Environment=ASPNETCORE_URLS=http://127.0.0.1:${PORT}
ExecStart=/srv/distin/distin/DistIN.Application
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now distin

echo "configuring web server..."

# helper: backup file if exists
backup_if_exists() {
  if [ -f "$1" ]; then
    cp -a "$1" "$1.bak.$(date +%s)"
  fi
}

if [ "$WEBSERVER" = "apache2" ]; then
  # ---------------- Apache start ----------------
  echo "checking/installing apache2 & certbot..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 certbot python3-certbot-apache
  a2enmod proxy proxy_http headers rewrite ssl reqtimeout

  echo "creating apache vHost for ${DOMAIN}..."
  SITE_CONF="/etc/apache2/sites-available/${DOMAIN}.conf"
  mkdir -p /var/www/letsencrypt/.well-known/acme-challenge/
  backup_if_exists "$SITE_CONF"

  cat >"$SITE_CONF" <<EOF
# ${DOMAIN} – Reverse Proxy für Kestrel (.NET) auf 127.0.0.1:${PORT}
<VirtualHost *:80>
    ServerName ${DOMAIN}

    # Upload/Timeouts großzügig
    LimitRequestBody 0
    ProxyTimeout 3600
    Timeout 3600
    RequestReadTimeout header=3600,MinRate=1 body=3600,MinRate=1

    # ACME-Challenge (aus Proxy ausnehmen)
    Alias /.well-known/acme-challenge/ /var/www/letsencrypt/.well-known/acme-challenge/
    <Directory "/var/www/letsencrypt/.well-known/acme-challenge/">
        Options None
        AllowOverride None
        Require all granted
    </Directory>
    ProxyPass /.well-known/acme-challenge/ !

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:${PORT}/ retry=0 timeout=3600 connectiontimeout=3600
    ProxyPassReverse / http://127.0.0.1:${PORT}/

    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"

    ErrorLog \${APACHE_LOG_DIR}/${DOMAIN}_error.log
    CustomLog \${APACHE_LOG_DIR}/${DOMAIN}_access.log combined
</VirtualHost>
EOF

  a2ensite "${DOMAIN}.conf"
  a2dissite 000-default.conf || true
  apache2ctl configtest
  systemctl reload apache2

  # UFW
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow "Apache Full" || true
    ufw delete allow "Apache" || true
  fi

  echo "configuring certbot..."
  certbot --apache -d "$DOMAIN" -m "$EMAIL" --agree-tos --redirect -n
  systemctl reload apache2
  echo "finished (apache)."
  # ---------------- Apache end ----------------

elif [ "$WEBSERVER" = "nginx" ]; then
  # ---------------- Nginx start ----------------
  echo "checking/installing nginx & certbot..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y nginx certbot python3-certbot-nginx

  # optional global baseline
  if ! grep -q "client_max_body_size" /etc/nginx/nginx.conf; then
    # GNU sed -i; ok auf Debian/Ubuntu
    sed -i 's/http {/http {\n    client_max_body_size 50m;/' /etc/nginx/nginx.conf
  fi

  SITE_AVAIL="/etc/nginx/sites-available/${DOMAIN}"
  SITE_ENABLED="/etc/nginx/sites-enabled/${DOMAIN}"
  mkdir -p /var/www/letsencrypt
  backup_if_exists "$SITE_AVAIL"

  echo "creating server block for ${DOMAIN}..."
  cat >"$SITE_AVAIL" <<EOF
# ${DOMAIN} – Reverse Proxy für Kestrel (.NET) auf 127.0.0.1:${PORT}
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    client_max_body_size 2g;

    location ^~ /.well-known/acme-challenge/ {
        default_type "text/plain";
        root /var/www/letsencrypt;
    }

    location / {
        proxy_pass         http://127.0.0.1:${PORT};
        proxy_http_version 1.1;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;

        proxy_set_header   Upgrade \$http_upgrade;
        proxy_set_header   Connection "upgrade";

        proxy_request_buffering off;
        proxy_buffering off;
        proxy_connect_timeout 3600s;
        proxy_send_timeout    3600s;
        proxy_read_timeout    3600s;
        send_timeout          3600s;
    }

    access_log /var/log/nginx/${DOMAIN}_access.log;
    error_log  /var/log/nginx/${DOMAIN}_error.log;
}
EOF

  ln -sf "$SITE_AVAIL" "$SITE_ENABLED"
  if [ -e /etc/nginx/sites-enabled/default ]; then
    rm -f /etc/nginx/sites-enabled/default
  fi

  echo "testing nginx configuration..."
  nginx -t
  systemctl reload nginx

  # UFW
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow "Nginx Full" || true
    ufw delete allow "Nginx HTTP" || true
  fi

  echo "configuring certbot..."
  certbot --nginx -d "$DOMAIN" -m "$EMAIL" --agree-tos --redirect -n
  systemctl reload nginx
  echo "finished (nginx)."
  # ---------------- Nginx end ----------------
else
  echo "invalid web server parameter"
  exit 1
fi

echo "All done. Domain: https://${DOMAIN}  |  Proxy → http://127.0.0.1:${PORT}"

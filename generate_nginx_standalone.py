#!/usr/bin/env python3
import sys
import os
import argparse
import validators
from urllib.parse import urlparse


def generate_nginx_defaults(args):

    result_url = urlparse(args.server_base_url)
    # if .path property is empty it means the url is just the domain w/ no additional route (e.g.: != http://sub.domain.tld/custom-route/)
    if result_url.path == '/' or result_url.path == '':
        custom_route = ''
        http_proxy_location = ''
        https_proxy_location = ''
        static_block = """
location /static {
      alias /opt/mhn/static;
    }
"""
    # if .path property not empty, it means some path defined after tld (e.g.: sub.domain.tld/custom/stuff/here/)
    else:
        custom_path = result_url.path
        # if there are one or more leading or trailing slashes, remove them
        custom_path = custom_path.strip('/')
        # now, custom_route should contain a str like 'custom/stuff/here'
        custom_route = custom_path
        http_proxy_location = """
    location / {{
        proxy_pass         http://localhost/{custom_route}/;
        proxy_redirect off;
        proxy_read_timeout 60s;
        proxy_set_header   Host            $host;
        proxy_set_header   X-Real-IP       $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
""".format(custom_route=custom_route)
        https_proxy_location = """
    location / {{
        proxy_pass         https://localhost/{custom_route}/;
        proxy_redirect off;
        proxy_read_timeout 60s;
        proxy_set_header   Host            $host;
        proxy_set_header   X-Real-IP       $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
""".format(custom_route=custom_route)
        static_block = """
    location /{custom_route}/static {{
        alias /opt/mhn/static;
    }}

    location = /static {{
        rewrite ^ /{custom_route}/static;
    }}
""".format(custom_route=custom_route)

    chnserver_template = """# Generated from generate_nginx_default_config.py
# this file is read from /opt/nginx/sites-available/default
server {{
    listen       80;
    server_name  _;
    
    location /{custom_route} {{
        try_files \\$uri @mhnserver;
    }}

    root /opt/www;
    location @mhnserver {{
      include uwsgi_params;
      uwsgi_pass unix:/tmp/uwsgi.sock;
    }}
    
    {http_proxy_location}

    {static_block}
}}

server {{
    #server_name
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    # certs sent to the client in SERVER HELLO are concatenated in ssl_certificate
    ssl_certificate /tls/cert.pem;
    ssl_certificate_key /tls/key.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;


    # modern configuration. tweak to your needs.
    ssl_protocols TLSv1.2;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256';
    ssl_prefer_server_ciphers on;

    # HSTS (ngx_http_headers_module is required) (15768000 seconds = 6 months)
    # add_header Strict-Transport-Security max-age=15768000;

    # OCSP Stapling ---
    # fetch OCSP records from URL in ssl_certificate and cache them
    ssl_stapling on;
    ssl_stapling_verify on;

    ## verify chain of trust of OCSP response using Root CA and Intermediate certs
    ## only use this with real (non-self-signed) certs
    #ssl_trusted_certificate /etc/pki/tls/certs/cert.pem;

#   resolver <IP DNS resolver>;

    location /{custom_route} {{
        try_files \\$uri @mhnserver;
    }}

    root /opt/www;
    location @mhnserver {{
      include uwsgi_params;
      uwsgi_pass unix:/tmp/uwsgi.sock;
    }}

    {https_proxy_location}

    {static_block}
}}
    """.format(
        custom_route=custom_route,
        http_proxy_location=http_proxy_location,
        https_proxy_location=https_proxy_location,
        static_block=static_block
    )

    if not os.path.exists(args.output_file_nginx) or args.force_overwrite:
        f = open(args.output_file_nginx, 'w')
        f.write(chnserver_template)
        f.close()
        print("Wrote file to %s" % args.output_file_nginx)
    else:
        sys.stderr.write("Not writing file, add -f to override\n")


def check_url(url):
    """
    Make sure this is a real URL
    """
    if validators.url(url):
        return url
    else:
        raise argparse.ArgumentTypeError("%s is an invalid url" % url)


def parse_args():

    parser = argparse.ArgumentParser(
        description='Generate nginx default conf file using some sane defaults'
    )
    parser.add_argument(
        '-s', '--server-base-url', help='Public URL for your CHN Server',
        required=True, type=check_url
    )
    parser.add_argument(
        '-n', '--output-file-nginx', required=True,
        help='File path to write nginx default out to'
    )
    parser.add_argument(
        '-f', '--force-overwrite', action='store_true',
        help='Forcibly overwrite file, even if it exists'
    )

    return parser.parse_args()


def main():
    args = parse_args()
    generate_nginx_defaults(args)


if __name__ == "__main__":
    sys.exit(main())

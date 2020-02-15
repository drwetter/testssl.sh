#!/bin/bash

image="rsnow/nginx"
docker pull $image
ID=$(docker run -d -ti $image)

echo $ID

[[ -z "$ID" ]] && echo "container couldn't be retrieved" >&2 && exit 1

docker exec -ti $ID nginx -V
docker exec -ti $ID mkdir /etc/nginx/ssl
HN=$(docker exec -ti $ID hostname| tr -d '\n' | tr -d '\r')

cd /tmp
cat >$ID.conf << EOF

server {
        listen 443 ssl default_server;
        listen [::]:443 ssl default_server;
        server_name _;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_early_data on;
        #
        ssl_certificate /etc/nginx/ssl/$HN.crt;
        ssl_certificate_key /etc/nginx/ssl/$HN.key;

	location / {
        	root   /usr/share/nginx/html;
        	index  index.html index.htm;
    	}
    	error_page   500 502 503 504  /50x.html;
    	location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
EOF

docker cp $ID.conf $ID:/etc/nginx/conf.d/443.conf

C_ST_etc="C=DE/ST=Gotham/L=Nowhere/CN=${HN}"
openssl req -subj "/${C_ST_etc}/CN=${HN}" -newkey rsa:4096 -keyout "$HN.key" -nodes -sha256 -out "$HN.req"
openssl x509  -days 365  -in "$HN.req" -req -signkey "$HN.key" -out "$HN.crt"
docker cp $HN.key $ID:/etc/nginx/ssl
docker cp $HN.crt $ID:/etc/nginx/ssl

docker exec -ti $ID nginx -s reload
# docker start $ID

echo
echo "You may now run \"testssl.sh $(docker inspect $ID --format '{{.NetworkSettings.IPAddress}}')\""

exit 0


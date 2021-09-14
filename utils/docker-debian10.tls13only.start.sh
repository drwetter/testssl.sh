
# no early data, but TLS 1.3 with debian:buster (sid similar in Feb 2019)

image=${1:-"debian:buster"}
docker pull "$image"
ID=$(docker run -d -ti $image)

[[ -z "$ID" ]] && echo "container couldn't be retrieved" >&2 && exit 1

docker exec -ti $ID apt-get update
docker exec -ti $ID apt-get install -y ssl-cert dialog
docker exec -ti $ID apt-get install -y nginx-common nginx-light
docker exec -ti $ID cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak
docker exec -ti $ID sed -i -e 's/# listen/listen/' -e 's/# include/include/' /etc/nginx/sites-available/default
if echo "$0" | grep -q only; then
	docker exec -ti $ID sed -i -e 's/listen \[::\]:443 ssl default_server;/&\n\tssl_protocols           TLSv1\.3;\n\tssl_ecdh_curve          X448:X25519;/' /etc/nginx/sites-available/default
else
	docker exec -ti $ID sed -i -e 's/listen \[::\]:443 ssl default_server;/&\n\tssl_protocols           TLSv1\.2 TLSv1\.3;\n\tssl_ecdh_curve          X448:X25519;/' /etc/nginx/sites-available/default
fi

docker exec -ti $ID nginx -V
docker exec -ti $ID service nginx start
docker exec -ti $ID service nginx status
# P Q

docker inspect $ID | jq -r '.[].NetworkSettings.IPAddress'

exit 0




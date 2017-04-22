#!/bin/bash

# simple check for seesion resumption 1) by SID, 2) by tickets
# Author: Dirk Wetter, GPLv2 see https://testssl.sh/LICENSE.txt


echo
echo "####################### session ID ######################"
openssl s_client -connect $1:443 -servername $1 -bugs -no_ssl2 -no_ticket -sess_out /tmp/ssl_s </dev/null &>/dev/null

echo "--------------------------------------------------------"
openssl s_client -connect $1:443 -servername $1 -bugs -no_ssl2 -no_ticket -sess_in /tmp/ssl_s </dev/null 2>/dev/null | egrep "New|Reused|SSL handshake has read"
echo "--------------------------------------------------------"

echo "####################### session ticket ######################"
openssl s_client -connect $1:443 -servername $1 -bugs -no_ssl2 -sess_out /tmp/ssl_s </dev/null &>/dev/null
echo "--------------------------------------------------------"
openssl s_client -connect $1:443 -servername $1 -bugs -no_ssl2 -sess_in /tmp/ssl_s  </dev/null 2>/dev/null| egrep "New|Reused|SSL handshake has read"

echo

ip="192.168.1.1"

scan_results=$(nmap -A -T4 -F $ip | grep "open" | awk -F' ' '{print $1","$3}')

OLDIFS=$IFS 
IFS="," 
while read port version
do

if [[ $version == "ssl/http" ]]; then

if [[ $port = "443" ]]; then

./testssl.sh/testssl.sh --csv --csvfile ./logs/scan.csv https://"$ip"

else

./testssl.sh/testssl.sh --csv --csvfile ./logs/scan.csv https://"$ip":"$port"

fi

fi

done <<< $scan_results
IFS=$OLDIFS

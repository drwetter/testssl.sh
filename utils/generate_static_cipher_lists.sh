#!/usr/bin/env bash
#
# vim:ts=5:sw=5:expandtab
# we have a spaces softtab, that ensures readability with other editors too

[ -z "$BASH_VERSINFO" ] && printf "\n\033[1;35m Please make sure you're using \"bash\"! Bye...\033[m\n\n" >&2 && exit 245
[ $(kill -l | grep -c SIG) -eq 0 ] && printf "\n\033[1;35m Please make sure you're calling me without leading \"sh\"! Bye...\033[m\n\n"  >&2 && exit 245

# This shell script generates the various static cipher lists that are used in testssl.sh.
# It should be re-run whenever new ciphers are added to cipher-mapping.txt to determine
# whether any of the variables in testssl.sh containing cipher lists need to be updated.

# debugging help:
readonly PS4='${LINENO}> ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'

COLOR=${COLOR:-2}                       # 2: Full color, 1: b/w+positioning, 0: no ESC at all
readonly RUN_DIR=$(dirname "$0")
TESTSSL_INSTALL_DIR="${TESTSSL_INSTALL_DIR:-""}"   # if you run testssl.sh from a different path you can set either TESTSSL_INSTALL_DIR
CIPHERS_BY_STRENGTH_FILE=""

###### Cipher suite information #####
declare -i TLS_NR_CIPHERS=0
declare TLS_CIPHER_HEXCODE=()
declare TLS_CIPHER_OSSL_NAME=()
declare TLS_CIPHER_RFC_NAME=()
declare TLS_CIPHER_SSLVERS=()
declare TLS_CIPHER_KX=()
declare TLS_CIPHER_AUTH=()
declare TLS_CIPHER_ENC=()
declare TLS_CIPHER_EXPORT=()

###### output functions ######
# a little bit of sanitzing with bash internal search&replace -- otherwise printf will hiccup at '%' and '--' does the rest.
out(){
#     if [[ "$BASH_VERSINFO" -eq 4 ]]; then
          printf -- "%b" "${1//%/%%}"
#     else
#          /usr/bin/printf -- "${1//%/%%}"
#     fi
}
outln() { out "$1\n"; }
pr_off()          { [[ "$COLOR" -ne 0 ]] && out "\033[m"; }
pr_underline()    { [[ "$COLOR" -ne 0 ]] && out "\033[4m$1" || out "$1"; pr_off; }

if [[ $(uname) == "Linux" ]] ; then
     toupper() { echo -n "${1^^}" ;  }
     tolower() { echo -n "${1,,}" ;  }
else
     toupper() { echo -n "$1" | tr 'a-z' 'A-Z'; }
     tolower() { echo -n "$1" | tr 'A-Z' 'a-z' ; }
fi

# try very hard to determine the install path to get ahold of the mapping file.
# TESTSSL_INSTALL_DIR can be supplied via environment so that the cipher mapping and CA bundles can be found
# www.carbonwind.net/TLS_Cipher_Suites_Project/tls_ssl_cipher_suites_simple_table_all.htm
get_mapping_file() {
     local mac

     [[ -z "$TESTSSL_INSTALL_DIR" ]] && TESTSSL_INSTALL_DIR="$(dirname ${BASH_SOURCE[0]})"

     [[ -r "$RUN_DIR/etc/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$RUN_DIR/etc/cipher-mapping.txt"
     [[ -r "$RUN_DIR/../etc/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$RUN_DIR/../etc/cipher-mapping.txt"
     [[ -r "$TESTSSL_INSTALL_DIR/etc/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/etc/cipher-mapping.txt"
     if [[ ! -r "$CIPHERS_BY_STRENGTH_FILE" ]]; then
          [[ -r "$RUN_DIR/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$RUN_DIR/cipher-mapping.txt"
          [[ -r "$TESTSSL_INSTALL_DIR/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/cipher-mapping.txt"
     fi

     # we haven't found the cipher file yet...
     if [[ ! -r "$CIPHERS_BY_STRENGTH_FILE" ]] && which readlink &>/dev/null ; then
          readlink -f ls &>/dev/null && \
               TESTSSL_INSTALL_DIR=$(readlink -f $(basename ${BASH_SOURCE[0]})) || \
               TESTSSL_INSTALL_DIR=$(readlink $(basename ${BASH_SOURCE[0]}))
               # not sure whether Darwin has -f
          TESTSSL_INSTALL_DIR=$(dirname $TESTSSL_INSTALL_DIR 2>/dev/null)
          [[ -r "$TESTSSL_INSTALL_DIR/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/cipher-mapping.txt"
          [[ -r "$TESTSSL_INSTALL_DIR/etc/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/etc/cipher-mapping.txt"
     fi

     # still no cipher mapping file:
     if [[ ! -r "$CIPHERS_BY_STRENGTH_FILE" ]] && which realpath &>/dev/null ; then
          TESTSSL_INSTALL_DIR=$(dirname $(realpath ${BASH_SOURCE[0]}))
          CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/etc/cipher-mapping.txt"
          [[ -r "$TESTSSL_INSTALL_DIR/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/cipher-mapping.txt"
     fi

     # still no cipher mapping file (and realpath is not present):
     if [[ ! -r "$CIPHERS_BY_STRENGTH_FILE" ]] && which readlink &>/dev/null ; then
         readlink -f ls &>/dev/null && \
              TESTSSL_INSTALL_DIR=$(dirname $(readlink -f ${BASH_SOURCE[0]})) || \
              TESTSSL_INSTALL_DIR=$(dirname $(readlink ${BASH_SOURCE[0]}))
              # not sure whether Darwin has -f
          CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/etc/cipher-mapping.txt"
          [[ -r "$TESTSSL_INSTALL_DIR/cipher-mapping.txt" ]] && CIPHERS_BY_STRENGTH_FILE="$TESTSSL_INSTALL_DIR/cipher-mapping.txt"
     fi

     if [[ ! -r "$CIPHERS_BY_STRENGTH_FILE" ]] ; then
          outln "\nATTENTION: No cipher mapping file found!"
          exit -2
     fi

     while read TLS_CIPHER_HEXCODE[TLS_NR_CIPHERS] n TLS_CIPHER_OSSL_NAME[TLS_NR_CIPHERS] TLS_CIPHER_RFC_NAME[TLS_NR_CIPHERS] TLS_CIPHER_SSLVERS[TLS_NR_CIPHERS] TLS_CIPHER_KX[TLS_NR_CIPHERS] TLS_CIPHER_AUTH[TLS_NR_CIPHERS] TLS_CIPHER_ENC[TLS_NR_CIPHERS] mac TLS_CIPHER_EXPORT[TLS_NR_CIPHERS]; do
          TLS_NR_CIPHERS+=1
     done < $CIPHERS_BY_STRENGTH_FILE
}

get_robust_pfs_ciphers() {
     local -i i
     local pfs_cipher hexc pfs_cipher_list="" pfs_hex_cipher_list=""

     for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
          pfs_cipher="${TLS_CIPHER_RFC_NAME[i]}"
          if ( [[ "$pfs_cipher" == "TLS_DHE_"* ]] || [[ "$pfs_cipher" == "TLS_ECDHE_"* ]] ) && \
             [[ ! "$pfs_cipher" =~ "NULL" ]] && [[ ! "$pfs_cipher" =~ "DES" ]] && [[ ! "$pfs_cipher" =~ "RC4" ]] && \
             [[ ! "$pfs_cipher" =~ "PSK" ]]; then
               hexc="${TLS_CIPHER_HEXCODE[i]}"
               pfs_hex_cipher_list+=", ${hexc:2:2},${hexc:7:2}"
               [[ "${TLS_CIPHER_OSSL_NAME[i]}" != "-" ]] && pfs_cipher_list+=":${TLS_CIPHER_OSSL_NAME[i]}"
          fi
     done
     outln ; pr_underline "Robust PFS Cipher Lists for SSLv3 - TLSv1.2" ; outln
     echo "ROBUST_PFS_CIPHERS=\"${pfs_cipher_list:1}\""
     echo "ROBUST_PFS_CIPHERS_HEX=\"$(tolower "${pfs_hex_cipher_list:2}")\""
}

get_std_cipherlists() {
     local hexc hexcode strength
     local -i i
     local null_ciphers="" anon_ciphers="" adh_ciphers="" exp40_ciphers=""
     local exp56_ciphers="" exp_ciphers="" low_ciphers="" des_ciphers=""
     local medium_ciphers="" tdes_ciphers="" high_ciphers=""
     local sslv2_null_ciphers="" sslv2_anon_ciphers="" sslv2_adh_ciphers="" sslv2_exp40_ciphers=""
     local sslv2_exp56_ciphers="" sslv2_exp_ciphers="" sslv2_low_ciphers="" sslv2_des_ciphers=""
     local sslv2_medium_ciphers="" sslv2_tdes_ciphers="" sslv2_high_ciphers=""
     local using_sockets=true

     for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
          hexc="${TLS_CIPHER_HEXCODE[i]}"
          strength="${TLS_CIPHER_ENC[i]}"
          strength="${strength//\)/}"
          strength="${strength#*\(}"

          if [[ ${#hexc} -eq 9 ]]; then
               hexcode="${hexc:2:2},${hexc:7:2}"
               [[ "${TLS_CIPHER_ENC[i]}" == "Enc=None" ]] && \
                    null_ciphers+=", $hexcode"
               [[ "${TLS_CIPHER_AUTH[i]}" == "Au=None" ]] && \
                    anon_ciphers+=", $hexcode"
               [[ "${TLS_CIPHER_RFC_NAME[i]}" =~ "TLS_DH_anon_" ]] && \
                    adh_ciphers+=", $hexcode"
               [[ $strength -eq 40 ]] && exp40_ciphers+=", $hexcode"
#               [[ $strength -eq 56 ]] && exp56_ciphers+=", $hexcode"
               [[ $strength -eq 56 ]] && \
                    [[ "${TLS_CIPHER_EXPORT[i]}" == "export" ]] && \
                    exp56_ciphers+=", $hexcode"
               [[ "${TLS_CIPHER_EXPORT[i]}" == "export" ]] && \
                    exp_ciphers+=", $hexcode"
               if [[ "${TLS_CIPHER_AUTH[i]}" != "Au=None" ]]; then
#                    [[ $strength -le 64 ]] && low_ciphers+=", $hexcode"
                    [[ "${TLS_CIPHER_ENC[i]}" != "Enc=None" ]] && \
                         [[ $strength -le 64 ]] && \
                         [[ "${TLS_CIPHER_EXPORT[i]}" != "export" ]] && \
                         low_ciphers+=", $hexcode" 
                    [[ "${TLS_CIPHER_ENC[i]}" == "Enc=DES(56)" ]] && \
                         [[ "${TLS_CIPHER_EXPORT[i]}" != "export" ]] && \
                         des_ciphers+=", $hexcode"
                    [[ "${TLS_CIPHER_ENC[i]}" == "Enc=SEED(128)" ]] && \
                         medium_ciphers+=", $hexcode"
                    [[ "${TLS_CIPHER_ENC[i]}" == "Enc=RC4(128)" ]] && \
                         medium_ciphers+=", $hexcode"
                    [[ "${TLS_CIPHER_ENC[i]}" == "Enc=IDEA(128)" ]] && \
                         medium_ciphers+=", $hexcode"
                    [[ "${TLS_CIPHER_ENC[i]}" == "Enc=3DES(168)" ]] && \
                         tdes_ciphers+=", $hexcode"
                    [[ "${TLS_CIPHER_ENC[i]}" == "Enc=AES"* ]] && \
                         high_ciphers+=", $hexcode"
                    [[ "${TLS_CIPHER_ENC[i]}" == "Enc=Camellia"* ]] && \
                         high_ciphers+=", $hexcode"
                    [[ "${TLS_CIPHER_ENC[i]}" == "Enc=ChaCha20"* ]] && \
                         high_ciphers+=", $hexcode"
                    [[ "${TLS_CIPHER_ENC[i]}" == "Enc=GOST"* ]] && \
                         high_ciphers+=", $hexcode"
                    [[ "${TLS_CIPHER_ENC[i]}" == "Enc=ARIA"* ]] && \
                         high_ciphers+=", $hexcode"
               fi
          else
               hexcode="${hexc:2:2},${hexc:7:2},${hexc:12:2}"
               [[ $strength -eq 40 ]] && sslv2_exp40_ciphers+=", $hexcode"
#               [[ $strength -eq 56 ]] && sslv2_exp56_ciphers+=", $hexcode"
               [[ "${TLS_CIPHER_EXPORT[i]}" == "export" ]] && \
                    sslv2_exp_ciphers+=", $hexcode"
#               [[ $strength -le 64 ]] && sslv2_low_ciphers+=", $hexcode"
               [[ $strength -le 64 ]] && \
                    [[ "${TLS_CIPHER_EXPORT[i]}" != "export" ]] && \
                    sslv2_low_ciphers+=", $hexcode"
               [[ "${TLS_CIPHER_ENC[i]}" == "Enc=DES(56)" ]] && \
                    sslv2_des_ciphers+=", $hexcode"
               [[ "${TLS_CIPHER_ENC[i]}" == "Enc=3DES(168)" ]] && \
                    sslv2_tdes_ciphers+=", $hexcode"
          fi
     done
     [[ -n "$null_ciphers" ]] && null_ciphers="${null_ciphers:2}, 00,ff"
     [[ -n "$anon_ciphers" ]] && anon_ciphers="${anon_ciphers:2}, 00,ff"
     [[ -n "$adh_ciphers" ]] && adh_ciphers="${adh_ciphers:2}, 00,ff"
     [[ -n "$exp40_ciphers" ]] && exp40_ciphers="${exp40_ciphers:2}, 00,ff"
     [[ -n "$exp56_ciphers" ]] && exp56_ciphers="${exp56_ciphers:2}, 00,ff"
     [[ -n "$exp_ciphers" ]] && exp_ciphers="${exp_ciphers:2}, 00,ff"
     [[ -n "$low_ciphers" ]] && low_ciphers="${low_ciphers:2}, 00,ff"
     [[ -n "$des_ciphers" ]] && des_ciphers="${des_ciphers:2}, 00,ff"
     [[ -n "$medium_ciphers" ]] && medium_ciphers="${medium_ciphers:2}, 00,ff"
     [[ -n "$tdes_ciphers" ]] && tdes_ciphers="${tdes_ciphers:2}, 00,ff"
     [[ -n "$high_ciphers" ]] && high_ciphers="${high_ciphers:2}, 00,ff"
     [[ -n "$sslv2_null_ciphers" ]] && sslv2_null_ciphers="${sslv2_null_ciphers:2}"
     [[ -n "$sslv2_anon_ciphers" ]] && sslv2_anon_ciphers="${sslv2_anon_ciphers:2}"
     [[ -n "$sslv2_adh_ciphers" ]] && sslv2_adh_ciphers="${sslv2_adh_ciphers:2}"
     [[ -n "$sslv2_exp40_ciphers" ]] && sslv2_exp40_ciphers="${sslv2_exp40_ciphers:2}"
     [[ -n "$sslv2_exp56_ciphers" ]] && sslv2_exp56_ciphers="${sslv2_exp56_ciphers:2}"
     [[ -n "$sslv2_exp_ciphers" ]] && sslv2_exp_ciphers="${sslv2_exp_ciphers:2}"
     [[ -n "$sslv2_low_ciphers" ]] && sslv2_low_ciphers="${sslv2_low_ciphers:2}"
     [[ -n "$sslv2_des_ciphers" ]] && sslv2_des_ciphers="${sslv2_des_ciphers:2}"
     [[ -n "$sslv2_medium_ciphers" ]] && sslv2_medium_ciphers="${sslv2_medium_ciphers:2}"
     [[ -n "$sslv2_tdes_ciphers" ]] && sslv2_tdes_ciphers="${sslv2_tdes_ciphers:2}"
     [[ -n "$sslv2_high_ciphers" ]] && sslv2_high_ciphers="${sslv2_high_ciphers:2}"

     outln ; pr_underline "Cipher lists for run_std_cipherlists()"; outln
     outln "null_ciphers=\"$(tolower "$null_ciphers")\""
     outln "sslv2_null_ciphers=\"$(tolower "$sslv2_null_ciphers")\""
     outln "anon_ciphers=\"$(tolower "$anon_ciphers")\""
     outln "sslv2_anon_ciphers=\"$(tolower "$sslv2_anon_ciphers")\""
     outln "adh_ciphers=\"$(tolower "$adh_ciphers")\""
     outln "sslv2_adh_ciphers=\"$(tolower "$sslv2_adh_ciphers")\""
     outln exp40_ciphers"=\"$(tolower "$exp40_ciphers")\""
     outln "sslv2_exp40_ciphers=\"$(tolower "$sslv2_exp40_ciphers")\""
     outln "exp56_ciphers=\"$(tolower "$exp56_ciphers")\""
     outln "sslv2_exp56_ciphers=\"$(tolower "$sslv2_exp56_ciphers")\""
     outln "exp_ciphers=\"$(tolower "$exp_ciphers")\""
     outln "sslv2_exp_ciphers=\"$(tolower "$sslv2_exp_ciphers")\""
     outln "low_ciphers=\"$(tolower "$low_ciphers")\""
     outln "sslv2_low_ciphers=\"$(tolower "$sslv2_low_ciphers")\""
     outln "des_ciphers=\"$(tolower "$des_ciphers")\""
     outln "sslv2_des_ciphers=\"$(tolower "$sslv2_des_ciphers")\""
     outln "medium_ciphers=\"$(tolower "$medium_ciphers")\""
     outln "sslv2_medium_ciphers=\"$(tolower "$sslv2_medium_ciphers")\""
     outln "tdes_ciphers=\"$(tolower "$tdes_ciphers")\""
     outln "sslv2_tdes_ciphers=\"$(tolower "$sslv2_tdes_ciphers")\""
     outln "high_ciphers=\"$(tolower "$high_ciphers")\""
     outln "sslv2_high_ciphers=\"$(tolower "$sslv2_high_ciphers")\""
}

get_cbc_ciphers() {
     local -i
     local hexc cbc_cipher_list="" cbc_cipher_list_hex=""

     # Want to keep ciphers lists to under 128 ciphers. Since there are a number of CBC ciphers
     # that do not currently have OpenSSL names, the ciphers with Null authentication can be
     # included in the OpenSSL list, but need to be excluded from the hex list.
     for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
          if [[ "${TLS_CIPHER_SSLVERS[i]}" != "SSLv2" ]] && [[ "${TLS_CIPHER_RFC_NAME[i]}" =~ CBC ]] && \
             [[ ! "${TLS_CIPHER_RFC_NAME[i]}" =~ PSK ]] && [[ ! "${TLS_CIPHER_RFC_NAME[i]}" =~ SRP ]] && \
             [[ ! "${TLS_CIPHER_RFC_NAME[i]}" =~ KRB5 ]]; then
               hexc="${TLS_CIPHER_HEXCODE[i]}"
               [[ "${TLS_CIPHER_AUTH[i]}" != "Au=None" ]] && cbc_cipher_list_hex+=", ${hexc:2:2},${hexc:7:2}"
               [[ "${TLS_CIPHER_OSSL_NAME[i]}" != "-" ]] && cbc_cipher_list+=":${TLS_CIPHER_OSSL_NAME[i]}"
          fi
     done
     
     outln ; pr_underline "CBC Ciphers for determine_tls_extensions()"; outln
     outln "cbc_cipher_list=\"${cbc_cipher_list:1}\""
     outln "cbc_cipher_list_hex=\"$(tolower "${cbc_cipher_list_hex:2}")\""
}


get_all_cbc_ciphers() {
     local -i
     local hexc cbc_ciphers="" cbc_ciphers_hex=""
     
     for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
          if [[ "${TLS_CIPHER_SSLVERS[i]}" != "SSLv2" ]] && [[ "${TLS_CIPHER_RFC_NAME[i]}" =~ CBC ]]; then
               hexc="${TLS_CIPHER_HEXCODE[i]}"
               cbc_ciphers_hex+=", ${hexc:2:2},${hexc:7:2}"
               [[ "${TLS_CIPHER_OSSL_NAME[i]}" != "-" ]] && cbc_ciphers+=":${TLS_CIPHER_OSSL_NAME[i]}"
          fi
     done
     
     outln ; pr_underline "CBC Ciphers for run_lucky13()"; outln
     outln "cbc_ciphers=\"${cbc_ciphers:1}\""
     outln "cbc_ciphers_hex=\"$(tolower "${cbc_ciphers_hex:2}")\""
}


get_sslv3_tls1_cbc_ciphers() {
     local -i
     local hexc cbc_ciphers="" cbc_ciphers_hex=""
     
     for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
          if [[ "${TLS_CIPHER_SSLVERS[i]}" != "SSLv2" ]] && [[ "${TLS_CIPHER_RFC_NAME[i]}" =~ CBC ]] && \
             [[ "${TLS_CIPHER_RFC_NAME[i]}" != *SHA256 ]] && [[ "${TLS_CIPHER_RFC_NAME[i]}" != *SHA384 ]]; then
               hexc="${TLS_CIPHER_HEXCODE[i]}"
               cbc_ciphers_hex+=", ${hexc:2:2},${hexc:7:2}"
               [[ "${TLS_CIPHER_OSSL_NAME[i]}" != "-" ]] && cbc_ciphers+=":${TLS_CIPHER_OSSL_NAME[i]}"
          fi
     done
     
     outln ; pr_underline "SSLv3/TLSv1.0 CBC Ciphers for run_ssl_poodle() and run_beast()"; outln
     outln "cbc_ciphers=\"${cbc_ciphers:1}\""
     outln "cbc_ciphers_hex=\"$(tolower "${cbc_ciphers_hex:2}")\""
}

get_export_rsa_ciphers() {
     local -i i
     local exportrsa_cipher_list="" exportrsa_tls_cipher_list_hex="" exportrsa_ssl2_cipher_list_hex=""

     for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
          if [[ "${TLS_CIPHER_EXPORT[i]}" == "export" ]] && \
               ( [[ "${TLS_CIPHER_KX[i]}" =~ RSA ]] || [[ "${TLS_CIPHER_AUTH[i]}" =~ RSA ]] ); then
               hexc="${TLS_CIPHER_HEXCODE[i]}"
               [[ "${TLS_CIPHER_SSLVERS[i]}" == "SSLv2" ]] && exportrsa_ssl2_cipher_list_hex+=", ${hexc:2:2},${hexc:7:2},${hexc:12:2}"
               [[ "${TLS_CIPHER_SSLVERS[i]}" != "SSLv2" ]] && exportrsa_tls_cipher_list_hex+=", ${hexc:2:2},${hexc:7:2}"
               [[ ! ":${exportrsa_cipher_list}:" =~ "${TLS_CIPHER_OSSL_NAME[i]}" ]] && exportrsa_cipher_list+=":${TLS_CIPHER_OSSL_NAME[i]}"
          fi
     done

     outln ; pr_underline "Export RSA ciphers for run_freak()"; outln
     outln "exportrsa_cipher_list=\"${exportrsa_cipher_list:1}\""
     outln "exportrsa_tls_cipher_list_hex=\"${exportrsa_tls_cipher_list_hex:2}\""
     outln "exportrsa_ssl2_cipher_list_hex=\"${exportrsa_ssl2_cipher_list_hex:2}\""
}

get_weak_dh_ciphers() {
     local -i
     local hexc exportdh_cipher_list="" exportdh_cipher_list_hex=""

     for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
          if [[ "${TLS_CIPHER_RFC_NAME[i]}" == "TLS_DHE_"* ]] && [[ "${TLS_CIPHER_EXPORT[i]}" == "export" ]]; then
               hexc="${TLS_CIPHER_HEXCODE[i]}"
               [[ "${TLS_CIPHER_OSSL_NAME[i]}" != "-" ]] && exportdh_cipher_list+=":${TLS_CIPHER_OSSL_NAME[i]}"
               exportdh_cipher_list_hex+=", ${hexc:2:2},${hexc:7:2}"
          fi
     done

     outln; pr_underline "Weak ephemeral DH ciphers for run_logjam()"; outln
     outln "exportdh_cipher_list=\"${exportdh_cipher_list:1}\""
     outln "exportdh_cipher_list_hex=\"${exportdh_cipher_list_hex:2}\""
}

get_dhe_ciphers() {
     local -i
     local hexc all_dh_ciphers=""

     for (( i=0; i < TLS_NR_CIPHERS; i++ )); do
          if [[ "${TLS_CIPHER_RFC_NAME[i]}" == "TLS_DHE_"* ]] || [[ "${TLS_CIPHER_RFC_NAME[i]}" == "TLS_DH_anon_"* ]]; then
               hexc="${TLS_CIPHER_HEXCODE[i]}"
               all_dh_ciphers+=", ${hexc:2:2},${hexc:7:2}"
          fi
     done

     outln; pr_underline "All ephemeral DH ciphers for run_logjam()"; outln
     outln "all_dh_ciphers=\"$(tolower "${all_dh_ciphers:2}")\""
}

get_mapping_file
get_robust_pfs_ciphers
get_std_cipherlists
get_all_cbc_ciphers
get_cbc_ciphers
get_sslv3_tls1_cbc_ciphers
get_export_rsa_ciphers
get_weak_dh_ciphers
get_dhe_ciphers
outln

exit $?

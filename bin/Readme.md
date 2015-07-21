
Binaries
========

The binaries here have the naming scheme ``openssl.$(uname).$(uname -m)``
and will be picked up from testssl.sh if you run testssl.sh directly
off the git directory.

They are compiled from Peter Mosmans openssl fork to support more advanced
ciphers as well as broken stuff which is either missing in most OS and
even in OpenSSL or LibreSSL.

More see ../openssl-bins/openssl-1.0.2-chacha.pm/

(Here you find the static binaries. If you want test Kerberos ciphers you
need to copy the binary hereto)

For contributors see ../CREDITS.md. 

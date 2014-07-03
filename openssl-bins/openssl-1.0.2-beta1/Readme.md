
Instructions
----

Both versions here are compiled from OpenSSL 1.0.2-beta1. The

* 64 bit version was compiled under Opensuse 12.3
* 32 bit version was compiled under Ubuntu 12.04 LTS

Both are statically linked, except a few libraries which are nowadays sometimes 
hard to link in, i.e. the dynamic loader (libdl) and glibc (libc).

If you want to compile OpenSSL yourself, here are my configure options:

### for 32 Bit:
> --prefix=/usr/ --openssldir=/etc/ssl enable-zlib enable-ssl2 enable-rc5 enable-rc2 enable-gost enable-cms enable-md2 enable-mdc2 enable-rc5 enable-ec enable-ec2m enable-ecdh enable-ecdsa enable-seed enable-idea -Wa,--noexecstack no-dane no-ec_nistp_64_gcc_128 no-gmp no-jpake no-krb5 no-libunbound no-multiblock no-rfc3779 no-sctp no-shared no-ssl-trace no-store no-zlib-dynamic static-engine

### for 64Bit:
> --prefix=/usr/ --openssldir=/etc/ssl enable-zlib enable-ssl2 enable-ec_nistp_64_gcc_128 enable-rc5 enable-rc2 enable-gost enable-cms enable-md2 enable-mdc2 enable-rc5 enable-ec enable-ec2m enable-ecdh enable-ecdsa enable-seed enable-idea -Wa,--noexecstack no-dane no-gmp no-jpake no-krb5 no-libunbound no-multiblock no-rfc3779 no-sctp no-shared no-ssl-trace no-store no-zlib-dynamic static-engine

And: You have to patch the sources, see file vanilla.patch otherwise you miss the experimental
and some RC4/MD5 cipher suites. "openssl ciphers -V 'ALL:COMPLEMENTOFALL' | wc -l" lists for me 150 
ciphers as opposed to 109 from Ubuntu or Opensuse. More soon to come!

**Don't use them for other purposes except testing!**


Enjoy,

Dirk



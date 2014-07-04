
Compilation instructions
========================

Currrent precompiled versions are are from OpenSSL 1.0.2i* You can
also pull a snapshot from git. This is a fork of OpenSSL from Peter Mosmans,
just to get chacha20+poly1305 support (thx!). Please note that the support
from official OpenSSL git repo doesn't work correctly and is not supported
(https://www.mail-archive.com/openssl-dev@openssl.org/msg34756.html)


> $ git clone https://github.com/PeterMosmans/openssl
> $ cd openssl

General instructions
--------------------

* 64 bit version was compiled under Opensuse 12.3
* 32 bit version was compiled under Ubuntu 12.04 LTS

In addition to the binaries statically linked binaries I provide -- except a few
libs which are nowadays sometimes hard to link -- I compiled a set of
dynamic binaries. The catch here are the Kerberos libs: No Linux
distributor privides static libs. As of now I feel to lazy to compile
MIT or KTH from scratch to get statitic libs.

So for the kerberos binaries I provide you need a whopping bunch of libraries which
you maybe need to install (libgssapi_krb5, libkrb5, libcom_err, libk5crypto, libkrb5support, 
libkeyutils). For the 'static' binaries kerberos is not compiled in, so that's is not needed.

If you want to compile OpenSSL yourself, here are the instructions:

0.) apply experimental-features.patch (otherwise you miss the experimental features)
1.) apply openssl-telnet-starttls.patch and openssl-telnet-starttls.patch
    (provided by Stefan Zehl, thx!). 

3.) configure the damned thing. Options I used:

* for 64Bit: 
>./config --prefix=/usr/ --openssldir=/etc/ssl enable-zlib enable-ssl2 enable-rc5 enable-rc2 enable-GOST enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa enable-seed enable-camellia enable-idea enable-rfc3779 enable-ec_nistp_64_gcc_128 --with-krb5-flavor=MIT experimental-jpake  

* for 32 Bit: >
./config --prefix=/usr/ --openssldir=/etc/ssl enable-zlib enable-ssl2 enable-rc5 enable-rc2 enable-GOST enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa enable-seed enable-camellia enable-idea enable-rfc3779 no-ec_nistp_64_gcc_128 --with-krb5-flavor=MIT experimental-jpake 

Don't use -DTEMP_GOST_TLS, it breaks things!

If you don't have Kerberos libraries and devel rpms/debs, omit "--with-krb5-flavor=MIT". 
If you have e.g. Heimdal --> figure out by yourself.

For real GOST cipher [1] support you need to built static libs as the crypto
engine is a shared lib (additional options: "shared -fPIC -DOPENSSL_PIC").
If you aiming at this you rather should compile everything with another prefix 
as you don't want your openssl binary to end up loading system libraries like libssl or
libcrypto. Alternatively you can hack the Makefile and include those
libs which you compiled statically as ".a".

4.) make depend
5.) make
6.) make report (check whether it runs ok)

7.) "openssl ciphers -V ALL:COMPLEMENTOFALL | wc -l" lists for me w/ kerberos and w/o GOST cipher engine
     167 ciphers as opposed to 111/109 from Ubuntu or Opensuse.

**Never use my binaries for anything else then for testing**


Enjoy,

Dirk


[1] https://en.wikipedia.org/wiki/GOST_%28block_cipher%29

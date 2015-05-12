
Compiling and Usage Instructions
================================

The precompiled binaries provided here have extended support for everything
which is normally not configured to be compiled (40+56 Bit, export/ANON ciphers, 
SSLv2 etc.). The binaries also come with extended support for new cipher suites 
and/or features which are not (yet?) in the official branch.

The binaries in this directory are all compiled from an OpenSSL 1.0.2 fork
from Peter Mosmans. He has patched the master git branch
to support CHACHA20 + POLY1305 and other ciphers like CAMELIA 256 Bit.

CHACHA20 + POLY1305 cipher suites from the official git repo didn't 
work for me work correctly, it's also likely they'll disappear shortly
(https://www.mail-archive.com/openssl-dev@openssl.org/msg34756.html).


General
-------

Both 64+32 bit versions were compiled under Ubuntu 12.04 LTS. Likely you
cannot use older distributions, younger worked in my test environments. I provide 
for each distributions two sets of binaries:

* completely statically linked binaries
* dynamically linked binaries, additionally with MIT Kerberos support ("krb5" in the name).
  They provide also KRB5-* and EXP-KRB5-* support (in OpenSSL terminology, see krb5-ciphers.txt). 

For the latter you need a whopping bunch of kerberos runtime libraries which you maybe need to 
install from your distributor (libgssapi_krb5, libkrb5, libcom_err, libk5crypto, libkrb5support, 
libkeyutils). The 'static' binaries do not have MIT kerberos support as there are no
static kerberos libs and I did not bother to compile them from the sources.


Compilation instructions
------------------------

If you want to compile OpenSSL yourself, here are the instructions:

1.) get openssl from Peter Mosmans' repo:

     git clone https://github.com/PeterMosmans/openssl
     cd openssl

2.) configure the damned thing. Options I used:

**for 64Bit including Kerberos ciphers:**

    ./config --prefix=/usr/ --openssldir=/etc/ssl enable-zlib enable-ssl2 enable-rc5 enable-rc2 \
    enable-GOST enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa \
    enable-seed enable-camellia enable-idea enable-rfc3779 enable-ec_nistp_64_gcc_128 \
    --with-krb5-flavor=MIT experimental-jpake  
    
**for 64Bit, static binaries:**    

    ./config --prefix=/usr/ --openssldir=/etc/ssl enable-zlib enable-ssl2 enable-rc5 enable-rc2 \
    enable-GOST enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa \
    enable-seed enable-camellia enable-idea enable-rfc3779 enable-ec_nistp_64_gcc_128 \
    -static experimental-jpake  

**for 32 Bit including Kerberos ciphers:**

    ./config --prefix=/usr/ --openssldir=/etc/ssl enable-zlib enable-ssl2 enable-rc5 enable-rc2 \
    enable-GOST enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa \
    enable-seed enable-camellia enable-idea enable-rfc3779 no-ec_nistp_64_gcc_128 \
    --with-krb5-flavor=MIT experimental-jpake 
    
 **for 32 Bit, static binaries:**

    ./config --prefix=/usr/ --openssldir=/etc/ssl enable-zlib enable-ssl2 enable-rc5 enable-rc2 \
    enable-GOST enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa \
    enable-seed enable-camellia enable-idea enable-rfc3779 no-ec_nistp_64_gcc_128 \
    -static experimental-jpake 

Don't use -DTEMP_GOST_TLS, it currently breaks things and it is not needed for general GOST [1] support.

So the difference ypu maybe spotted: If you don't have / don't want Kerberos libraries and devel rpms/debs, omit "--with-krb5-flavor=MIT" (see examples). 
If you have another Kerberos flavor you need to figure out by yourself.

3.) make depend

4.) make

5.) make report (check whether it runs ok!)

6.) "./apps/openssl ciphers -V 'ALL:COMPLEMENTOFALL' | wc -l" lists now for me 
* 191(+4 GOST) ciphers -- including kerberos
* 177(+4 GOST) ciphers without kerberos

as opposed to 111/109 from Ubuntu or Opensuse. 

Enjoy, Dirk

PS: **Never use these binaries for anything else then for testing**


[1] https://en.wikipedia.org/wiki/GOST_%29block_cipher%29

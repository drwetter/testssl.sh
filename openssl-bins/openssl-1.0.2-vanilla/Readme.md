

Instructions
============

The binaries here are provided as a courtesy. They still support SSLv2, SSLv3
and some "weak" ciphers which Linux distributors sometimes disable for security 
reasons.

They are all compiled from an OpenSSL 1.0.2 vanilla tree.


General
-------

Both 64+32 bit versions were compiled under Ubuntu 12.04 LTS. Likely you
cannot use older distributions, younger should work. I provide for each
distributions two sets of binaries:

* statically linked binaries
* dynamically linked binaries with MIT Kerberos support ("krb5" in the name)

For the latter you need a whopping bunch of kerberos libraries which you maybe need to 
install from your distributor (libgssapi_krb5, libkrb5, libcom_err, libk5crypto, libkrb5support, 
libkeyutils). For the 'static' binaries kerberos is not compiled in, so that's is not needed.



Compilation instructions
------------------------

If you want to compile OpenSSL yourself, here are the instructions:

1.) get openssl:

     wget https://www.openssl.org/source/openssl-1.0.2.tar.gz
     wget https://www.openssl.org/source/openssl-1.0.2.tar.gz.asc
     gpg --verify openssl-1.0.2.tar.gz.asc || echo "STOP!"
     tar xzf openssl-1.0.2.tar.gz
     cd openssl-1.0.2

2.)  patch it, see https://github.com/drwetter/testssl.sh/blob/master/openssl-bins/openssl-1.0.2-beta1/vanilla.patch

3.) configure the damned thing. Options I used:

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

If you don't have / don't want Kerberos libraries and devel rpms/debs, omit
"--with-krb5-flavor=MIT" (see examples). If you have other Kerberos flavors you
need to figure out by yourself.

4.) make depend && make

5.) make report (check whether it runs ok)

6.) "./apps/openssl ciphers -V 'ALL:COMPLEMENTOFALL' | wc -l" lists now for me 
* 164(+4 GOST) ciphers -- including kerberos
* 150(+4 GOST) ciphers without kerberos

as opposed to 111/109 from Ubuntu or Opensuse. 

Enjoy, Dirk

PS: **Never use these binaries for anything else then for testing**


[1] https://en.wikipedia.org/wiki/GOST_%29block_cipher%29

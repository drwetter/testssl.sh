
Binaries
========

All the precompiled binaries provided here have extended support for
everything which is normally not in OpenSSL or LibreSSL -- 40+56 Bit,
export/ANON ciphers, weak DH ciphers, weak EC curves, SSLv2 etc. -- all the dirty
features needed for testing. OTOH they also come with extended support
for new / advanced cipher suites and/or features which are not in the 
official branch like (old version of the) CHACHA20+POLY1305 and CAMELLIA 256 bit ciphers.
They also have IPv6 support, see below.

The (stripped) binaries this directory are all compiled from my openssl
snapshot (https://github.com/drwetter/openssl) from Peter Mosman's openssl
fork (https://github.com/PeterMosmans/openssl). Thx a bunch, Peter!

Compiled Linux and FreeBSD binaries so far come from Dirk, other
contributors see ../CREDITS.md .

**I discontinued to upload the not commonly used binaries at github ** (ARM7l, Darwin.i386 and all except one kerberos compiles) **as it is not very appropriate to use github especially for those. The main site for all 
binaries is https://testssl.sh/openssl-1.0.2i-chacha.pm.ipv6.contributed/, also see the tarball @
https://testssl.sh/openssl-1.0.2i-chacha.pm.ipv6.Linux+FreeBSD.tar.gz**

The binaries here have the naming scheme ``openssl.$(uname).$(uname -m)``
and will be picked up from testssl.sh if you run testssl.sh directly
off the git directory. Otherwise you need ``testssl.sh`` to point to it 
via the argument (``--openssl=<here>``) or as an environment variable
(``OPENSSL=<here> testssl.sh <yourargs>``).

The Linux binaries with the trailing ``-krb5`` come with Kerberos 5 support, 
they won't be picked up automatically as you need to make sure first they
run (see libraries below).


Compiling and Usage Instructions
================================

General
-------

Both 64+32 bit Linux binaries were compiled under Ubuntu 12.04 LTS. Likely you
cannot use them for older distributions, younger worked in all my test environments. 
I provide for each distributions two sets of binaries (no IPv6 here):

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

or use my repo:

    git clone https://github.com/drwetter/openssl
    cd openssl


2.) configure the damned thing. Options I used (see https://github.com/drwetter/testssl.sh/blob/master/utils/make-openssl.sh)

**for 64Bit including Kerberos ciphers:**

    ./config --prefix=/usr/ --openssldir=/etc/ssl enable-zlib enable-ssl2 enable-rc5 enable-rc2 \
    enable-GOST enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa \
    enable-seed enable-camellia enable-idea enable-rfc3779 enable-ec_nistp_64_gcc_128 \
    --with-krb5-flavor=MIT experimental-jpake -DOPENSSL_USE_BUILD_DATE

**for 64Bit, static binaries:**

    ./config --prefix=/usr/ --openssldir=/etc/ssl enable-zlib enable-ssl2 enable-rc5 enable-rc2 \
    enable-GOST enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa \
    enable-seed enable-camellia enable-idea enable-rfc3779 enable-ec_nistp_64_gcc_128 \
    -static experimental-jpake -DOPENSSL_USE_BUILD_DATE

**for 32 Bit including Kerberos ciphers:**

    ./config --prefix=/usr/ --openssldir=/etc/ssl enable-zlib enable-ssl2 enable-rc5 enable-rc2 \
    enable-GOST enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa \
    enable-seed enable-camellia enable-idea enable-rfc3779 no-ec_nistp_64_gcc_128 \
    --with-krb5-flavor=MIT experimental-jpake -DOPENSSL_USE_BUILD_DATE

 **for 32 Bit, static binaries:**

    ./config --prefix=/usr/ --openssldir=/etc/ssl enable-zlib enable-ssl2 enable-rc5 enable-rc2 \
    enable-GOST enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa \
    enable-seed enable-camellia enable-idea enable-rfc3779 no-ec_nistp_64_gcc_128 \
    -static experimental-jpake -DOPENSSL_USE_BUILD_DATE 

IPv6 support would need additionally the patch from ``fedora-dirk-ipv6.diff`` (included already
in my branch).  This doesn't give you the option of an IPv6 enabled proxy yet.
It is good practice to compile those binaries with ``-DOPENSSL_USE_IPV6`` as
later on you can tell them apart by``openssl version -a``.

Four GOST [1][2] ciphers come via engine support automagically with this setup. Two additional GOST 
ciphers can be compiled in (``GOST-GOST94``, ``GOST-MD5``) with ``-DTEMP_GOST_TLS`` but as of now they make 
problems under some circumstances, so unless you desperately need those ciphers I would stay away from 
``-DTEMP_GOST_TLS``.

If you don't have / don't want Kerberos libraries and devel rpms/debs, just omit "--with-krb5-flavor=MIT"
(see examples).  If you have another Kerberos flavor you would need to figure out by yourself.

3.) make depend

4.) make

5.) make report (check whether it runs ok!)

6.) ``./apps/openssl ciphers -V 'ALL:COMPLEMENTOFALL' | wc -l`` lists for me
* 193(+4 GOST) ciphers including kerberos 
* 179(+4 GOST) ciphers without kerberos

as opposed to ~110 from Ubuntu or Opensuse. 

**Never use these binaries for anything other than testing**

Enjoy, Dirk

[1] https://en.wikipedia.org/wiki/GOST_%29block_cipher%29

[2] http://fossies.org/linux/openssl/engines/ccgost/README.gost



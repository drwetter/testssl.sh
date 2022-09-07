
Binaries
========

All the precompiled binaries provided here have extended support for
everything which is normally not in OpenSSL or LibreSSL -- 40+56 Bit,
export/ANON ciphers, weak DH ciphers, weak EC curves, SSLv2 etc. -- all the dirty
features needed for testing. OTOH they also come with extended support
for some new / advanced cipher suites and/or features which are not in the
official branch like (old version of the) CHACHA20+POLY1305 and CAMELLIA 256 bit ciphers.

The (stripped) binaries this directory are all compiled from my openssl snapshot
(https://github.com/drwetter/openssl-1.0.2.bad) which adds a few bits to Peter
Mosman's openssl fork (https://github.com/PeterMosmans/openssl). Thx a bunch, Peter!
The few bits are IPv6 support (except IPV6 proxy) and some STARTTLS backports.

Compiled Linux and FreeBSD binaries so far come from Dirk, other
contributors see ../CREDITS.md .

The binaries here have the naming scheme ``openssl.$(uname).$(uname -m)``
and will be picked up from testssl.sh if you run testssl.sh directly
off the git directory. Otherwise you need ``testssl.sh`` to point to it
via the argument (``--openssl=<here>``) or as an environment variable
(``OPENSSL=<here> testssl.sh <yourargs>``).

The Linux binaries with the trailing ``-krb5`` come with Kerberos 5 support,
they won't be picked up automatically as you need to make sure first they
run (see libraries below).

Because I didn't want blow up the repo and waste disk spaces for others
there are more binaries for other aerchitectures (ARM7l, Darwin.i386, ..
here: https://testssl.sh/openssl-1.0.2k-chacha.pm.ipv6.Linux+FreeBSD.tar.gz
and older ones here: https://testssl.sh/openssl-1.0.2i-chacha.pm.ipv6.contributed/ .

As there is not darwin64-arm64-cc in the old branch there is not binary for
that architecture either. (FYI: patch isn't big but isn't easy to backport).


In general the usage of this binaries became more and more of a limited
value: It doesn't support e.g. TLS 1.3 and newer TLS 1.2 ciphers. OTOH servers
which only offer SSLv2 and SSLv3 became less common and we use for the
majority of checks in testssl.sh sockets and not this binary.


Compiling and Usage Instructions
================================

General
-------

Both 64+32 bit Linux binaries were compiled under Ubuntu 12.04 LTS(!). Likely you
cannot use them for older distributions, younger worked in all my test environments
(like Debian 11 and OpenSuse Tumbleweed on Q3/2022).

I provide two sets of binaries:

* completely statically linked binaries
* dynamically linked binaries, additionally with MIT Kerberos support ("krb5" in the name).
  They provide also KRB5-* and EXP-KRB5-* support (in OpenSSL terminology, see krb5-ciphers.txt).

For the latter you need a whopping bunch of kerberos runtime libraries which you maybe need to
install from your distributor (libgssapi_krb5, libkrb5, libcom_err, libk5crypto, libkrb5support,
libkeyutils). Despite the fact it's 2022 the openssl kerberos binary still works when compiled
non-statically on a legacy VM. I didn't bother use static kerberos libs as they need to be
compiled from source.


Compilation instructions
------------------------

If you want to compile OpenSSL yourself, here are the instructions:

1.)
    git git clone https://github.com/drwetter/openssl-1.0.2-bad
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

as opposed to ~162 from Ubuntu or Opensuse. Note that newer distributions provide
newer ciphers which this old openssl-1.0.2-bad doesn't have. OTOH openssl-1.0.2-bad
has a lot of legacy ciphers and protocols enabled which newer binaries don't have.

**Never use these binaries for anything other than testing!**

Enjoy, Dirk

[1] https://en.wikipedia.org/wiki/GOST_%29block_cipher%29

[2] http://fossies.org/linux/openssl/engines/ccgost/README.gost

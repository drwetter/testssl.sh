
## Intro

[![Build Status](https://travis-ci.org/drwetter/testssl.sh.svg?branch=master)](https://travis-ci.org/drwetter/testssl.sh)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/drwetter/testssl.sh?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

`testssl.sh` is a free command line tool which checks a server's service on
any port for the support of TLS/SSL ciphers, protocols as well as some
cryptographic flaws.

#### Key features

* Clear output: you can tell easily whether anything is good or bad
* Machine readable output
* Ease of installation: Linux, OSX/Darwin, FreeBSD, NetBSD, MSYS2/Cygwin,
  WSL work out of the box (OpenBSD needs bash). No need to install
  or to configure something.  No gems, CPAN, pip or the like
* Flexibility: You can test any SSL/TLS enabled and STARTTLS service, not
  only web servers at port 443
* Toolbox: Several command line options help you to run YOUR test and
  configure YOUR output
* Reliability: features are tested thoroughly
* Privacy: It's only you who sees the result, not a third party
* Freedom: It's 100% open source. You can look at the code, see what's
  going on
* The development is open (github) and participation is welcome.

#### License

This software is free. You can use it under the terms of GPLv2, see LICENSE.
In addition starting from version 3.0rc1 if you're offering a scanner based on testssl.sh
as a public and / or paid service in the internet you need to mention to your audience that you're using
this program and where to get this program from.

#### Installation

You can download testssl.sh by cloning this git repository:

    git clone --depth 1 https://github.com/drwetter/testssl.sh.git

Or help yourself downloading the ZIP archive
https://github.com/drwetter/testssl.sh/archive/2.9dev.zip.  ``testssl.sh --help``
will give you some help upfront.  More help: see doc directory with
man pages. Older sample runs are at https://testssl.sh/.

#### Running a docker container from dockerhub

     docker run -ti drwetter/testssl.sh <your_cmd_line>

#### Status

In the 2.9dev branch we're developing the 3.0 release. We're currently in the
release candidate phase. That means you can and should use it for production
and let us know if you encounter any additional bugs.

For the previous stable version please see release
[2.9.5](https://github.com/drwetter/testssl.sh/tree/2.9.5) which is is the
successor of 2.8 and stable for day-to-day work. Support for 2.9.5 will be 
soon dropped. 2.8 is not supported anymore.

#### Compatibility

testssl.sh is working on every Linux/BSD distribution out of the box. Since 2.9dev
most of the limitations of disabled features from the openssl client are gone
due to bash-socket-based checks. As a result you can also use e.g. LibreSSL or OpenSSL
1.1.1. testssl.sh also works on other unixoid system out of the box, supposed they have
`/bin/bash` >= version 3.2 and standard tools like sed and awk installed.
System V needs to have GNU grep installed. MacOS X and Windows (using MSYS2 or
cygwin) work too. OpenSSL version  version >= 1.0.2 is recommended for better
LOGJAM checks and to display bit strengths for key exchanges.

Update notification here or @ [twitter](https://twitter.com/drwetter).

#### Features implemented in [2.9dev](Readme.md#devel) (as opposed to [2.9.5](https://github.com/drwetter/testssl.sh/blob/2.9.5/Readme.md#features-implemented-in-295))
* Full support of TLS 1.3, shows also drafts supported
* ROBOT check
* Better TLS extension support
* Better OpenSSL 1.1.1 support
* DNS over Proxy and other proxy improvements
* Decoding of unencrypted BIG IP cookies
* Better JSON output: renamed IDs and findings shorter/better parsable
* JSON output now valid also for non-responding servers
* Testing now per default 370 ciphers
* Further improving the robustness of TLS sockets (sending and parsing)
* Support of supplying timeout value for ``openssl connect`` -- useful for batch/mass scanning
* File input for serial or parallel mass testing can be also in nmap grep(p)able (-oG) format
* LOGJAM: now checking also for DH  and FFDHE groups (TLS 1.2)
* PFS: Display of elliptical curves supported, DH and FFDHE groups (TLS 1.2 + TLS 1.3)
* Check for session resumption (Ticket, ID)
* TLS Robustness check (GREASE)
* Expect-CT Header Detection
* --phone-out does certificate revocation checks via OCSP (LDAP+HTTP) and with CRL
* Fully OpenBSD and LibreSSL support
* Missing SAN warning
* Added support for private CAs
* Man page reviewed
* Better error msg suppression (not fully installed OpenSSL)
* Way better handling of connectivity problems
* Exit codes better: 0 for running without error, 1+n for small errors, >240 for major errors.
* Dockerfile and repo @ docker hub with that file (see above)
* Java Root CA store added
* Better support for XMPP via STARTTLS & faster
* Certificate check for to-name in stream of XMPP
* Support for NNTP via STARTTLS
* More robustness for any STARTTLS protocol (fall back to plaintext while in TLS)
* Fixed TCP fragmentation
* Added `--ids-friendly` switch

[Planned for 3.0](https://github.com/drwetter/testssl.sh/milestone/4).


#### Documentation

* There's a man page in groff, html and markdown format in `~/doc/`.
* https://testssl.sh/ will help to get you started.
* Will Hunt provides a longer, good [description](https://www.4armed.com/blog/doing-your-own-ssl-tls-testing/) for the version 2.8, including useful background info.


#### Contributions

Contributions, feedback,  bug reports are welcome! For contributions please
note: One patch per feature -- bug fix/improvement. Please test your
changes thoroughly as reliability is important for this project.

There's a [coding guideline](https://github.com/drwetter/testssl.sh/wiki/Coding-Style).

#### Bug reports

Please file bugs in the issue tracker. Do not forget to provide detailed information,
see https://github.com/drwetter/testssl.sh/wiki/Bug-reporting. Nobody can read your
thoughts -- yet. And only agencies your screen ;-)

----

## External/related projects

Please address questions not specifically to the code of testssl.sh to the
respective projects

#### Cool web frontend
* https://github.com/TKCERT/testssl.sh-webfrontend

#### Mass scanner w parallel scans and elastic searching the results
* https://github.com/TKCERT/testssl.sh-masscan

#### Another ready-to-go docker image is at:
* https://quay.io/repository/jumanjiman/testssl

#### Privacy checker using testssl.sh
* https://privacyscore.org

#### Brew package

* see [#233](https://github.com/drwetter/testssl.sh/issues/233) and
  [https://github.com/Homebrew/homebrew](https://github.com/Homebrew/homebrew)

#### Daemon for batch execution of testssl.sh command files
* https://github.com/bitsofinfo/testssl.sh-processor

#### Daemon for batch processing of testssl.sh JSON result files for sending Slack alerts, reactive copying etc
* https://github.com/bitsofinfo/testssl.sh-alerts

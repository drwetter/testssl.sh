
## Intro

[![Build Status](https://github.com/drwetter/testssl.sh/actions/workflows/test.yml/badge.svg)](https://github.com/drwetter/testssl.sh/actions/workflows/test.yml)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/drwetter/testssl.sh?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

`testssl.sh` is a free command line tool which checks a server's service on
any port for the support of TLS/SSL ciphers, protocols as well as some
cryptographic flaws.

### Key features

* Clear output: you can tell easily whether anything is good or bad.
* Machine readable output.
* No installation needed: Linux, OSX/Darwin, FreeBSD, NetBSD, MSYS2/Cygwin,  WSL work out of the box. Only OpenBSD needs bash. No need to install  or to configure something.  No gems, CPAN, pip or the like.
* A Dockerfile is provided, there's also an official container @ dockerhub.
* Flexibility: You can test any SSL/TLS enabled and STARTTLS service, not only web servers at port 443.
* Toolbox: Several command line options help you to run *your* test and configure *your* output.
* Reliability: features are tested thoroughly.
* Privacy: It's only you who sees the result, not a third party.
* Freedom: It's 100% open source. You can look at the code, see what's going on.
* The development is open (github) and participation is welcome.

### License

This software is free. You can use it under the terms of GPLv2, see LICENSE.

Attribution is important for the future of this project -- also in the
internet. Thus if you're offering a scanner based on testssl.sh as a public and/or
paid service in the internet you are strongly encouraged to mention to your audience
that you're using this program and where to get this program from. That helps us
to get bugfixes, other feedback and more contributions.

### Compatibility

testssl.sh is working on every Linux/BSD distribution out of the box. Latest by 2.9dev
most of the limitations of disabled features from the openssl client are gone
due to bash-socket-based checks. As a result you can also use e.g. LibreSSL or OpenSSL
1.1.1 . testssl.sh also works on other unixoid systems out of the box, supposed they have
`/bin/bash` >= version 3.2 and standard tools like sed and awk installed. An implicit
(silent) check for binaries is done when you start testssl.sh . System V needs probably
to have GNU grep installed. MacOS X and Windows (using MSYS2, Cygwin or WSL) work too.

Update notification here or @ [twitter](https://twitter.com/drwetter).

### Installation

You can download testssl.sh by cloning this git repository:

    git clone --depth 1 https://github.com/drwetter/testssl.sh.git --branch 3.0


For the stable version help yourself by downloading the [ZIP](https://codeload.github.com/drwetter/testssl.sh/zip/3.0.6) or the latest testssl-3.0.X.tar.gz from [https://testssl.sh](https://testssl.sh/) archive. Just ``cd`` to the directory created (=INSTALLDIR) and run it off there.

#### Docker

Testssl.sh has minimal requirements. As stated you don't have to install or build anything. You can just run it from the pulled/cloned directory. Still if you don't want to pull the github repo to your directory of choice you can pull a container from dockerhub and run it:
```
docker run --rm -ti drwetter/testssl.sh:3.0 <your_cmd_line>
```
Or if you have cloned this repo you also can just ``cd`` to the INSTALLDIR (change to 3.0, do a git pull) and run
```
docker build . -t drfooimage && docker run --rm -t drfooimage example.com
```

For more please consult [Dockerfile.md](https://github.com/drwetter/testssl.sh/blob/3.0/Dockerfile.md).

### Status

This is the stable 3.0 version. That means you can and should use it for production and let us know if you encounter any additional bugs. Features implemented in 3.0 are listed in the [Changelog](https://github.com/drwetter/testssl.sh/blob/3.0/CHANGELOG.md). Support for 2.9.5 has been dropped.

The version 3.0 receives bugfixes, labeled as 3.0.1, 3.0.2 and so on. This will happen until 3.2 is released. Development is taking place in the [3.1dev](https://github.com/drwetter/testssl.sh/tree/3.1dev) branch which will eventually lead to version 3.2. We try to keep 3.1dev as solid as possible but things will certainly change in 3.1dev. Think of the 3.1dev branch like a rolling release.


### Documentation

* .. it is there for reading. Please do so :-) -- at least before asking questions. See man page in groff, html and markdown format in `~/doc/`.
* [https://testssl.sh/](https://testssl.sh/) will help to get you started.
* Albeit a bit older Will Hunt provides a longer, good [description](https://www.4armed.com/blog/doing-your-own-ssl-tls-testing/) for the (older) version 2.8, including useful background info.


### Contributing

Contributions are welcome! See [CONTRIBUTING.md](https://github.com/drwetter/testssl.sh/blob/3.0/CONTRIBUTING.md) for details.

### Bug reports

Bug reports are important. It makes this project more robust.

Please file bugs in the issue tracker @ github. Do not forget to provide detailed information, see template for issue, and further details @ https://github.com/drwetter/testssl.sh/wiki/Bug-reporting. Nobody can read your thoughts -- yet. And only agencies your screen ;-)

You can also debug yourself, see [here](https://github.com/drwetter/testssl.sh/wiki/Findings-and-HowTo-Fix-them).

----

### External/related projects

Please address questions not specifically to the code of testssl.sh to the respective projects below.

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

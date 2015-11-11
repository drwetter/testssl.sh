
## Intro

[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/drwetter/testssl.sh?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

`testssl.sh` is a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws. 

####Key features

* Clear output: you can tell easily whether anything is good or bad
* Ease of installation: It works for Linux, Darwin, FreeBSD and MSYS2/Cygwin out of the box: no need to install or configure something, no gems, CPAN, pip or the like.
* Flexibility: You can test any SSL/TLS enabled and STARTTLS service, not only webservers at port 443
* Toolbox: Several command line options help you to run YOUR test and configure YOUR output
* Reliability: features are tested thoroughly
* Verbosity: If a particular check cannot be performed because of a missing capability on your client side, you'll get a warning
* Privacy: It's only you who sees the result, not a third party
* Freedom: It's 100% open source. You can look at the code, see what's going on and you can change it. 
* Heck, even the development is open (github)

####General

Here in the master branch you find the development version of the software -- with new features and maybe some bugs. For the stable version and **a more thorough description of the command line options** please see [testssl.sh](https://testssl.sh/ "Go to the site with the stable version and more documentation"). 

testssl.sh is working on every Linux/BSD distribution out of the box with some limitations of disabled features from the openssl client -- some workarounds are done with bash-socket-based checks. It also works on other unixoid system out of the box, supposed they have `/bin/bash` and standard tools like sed and awk installed. MacOS X and Windows (using MSYS2 or cygwin) work too. OpenSSL version >= 1 is a must.  OpenSSL version >= 1.0.2 is needed for better LOGJAM checks and to display bit strengths for key exchanges.

####Current Development

Planned features in the release 2.7dev/2.8 are: 

https://github.com/drwetter/testssl.sh/milestones/2.7dev%20%282.8%29

Done so far:

* Trust chain check against certificate stores from java, linux (system), microsoft, mozilla (works for openssl >=1.0.2)
* IPv6 (status: 80% working, details see https://github.com/drwetter/testssl.sh/issues/11
* works on servers requiring a client certificate for authentication
* SSL Session ID check
* avahi/mDNS based name resolution
* Logging to a file
* Even more compatibilty improvements for FreeBSD, RH-ish and F5 systems

Contributions, feedback, also bug reports are welcome! For contributions please note: One patch per feature -- bug fix/improvement. Please test your changes thouroughly as reliability is important for this project. 

Please file bug reports @ https://github.com/drwetter/testssl.sh/issues .

Update notification here or @ [twitter](https://twitter.com/drwetter). 

----

## External contributions

Please address questions not specifically to the code of testssl.sh to the respective projects

#### Docker

Docker images are available at:

* https://quay.io/repository/jumanjiman/testssl
* https://hub.docker.com/r/mvance/testssl/

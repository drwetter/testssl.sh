Please make sure that you provide enough information so that we understand what your issue is about.

1. ``uname -a``

2. testssl version from the banner: ``testssl.sh -b 2>/dev/null | head -4 | tail -2``

3. ``git log | head -1`` (if running from git repo). Important: If in doubt check the git log and/or check whether you run the lastest 3.0 version from the git repo.

4. openssl and bash version used by testssl.sh: ``testssl.sh -b 2>/dev/null | grep Using``

5. steps to reproduce: testssl.sh or docker command line, if possible incl. host

6. what exactly was happening, output is needed

7. what did you expect instead?


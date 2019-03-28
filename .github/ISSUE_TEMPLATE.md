Please make sure that you provide enough information so that we understand what your issue is about.

1. uname -a
   
2. testssl version from the banner: testssl.sh -b 2>/dev/null | head -4 | tail -2

3. git log | head -1 (if running from git repo)

4. openssl version: testssl.sh -b 2>/dev/null | awk -F':' '/openssl/ { print $2}'

4. steps to reproduce: testssl.sh or docker command line, if possible incl. host

5. what exactly was happening, output is needed

6. what did you expect instead?


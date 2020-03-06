Please make sure that you provide enough information so that we understand what your issue is about.

0. Did you check the documentation in ~/doc/ or, if it is a different problem: Did you google for it?

1. uname -a
   
2. testssl version from the banner: testssl.sh -b 2>/dev/null | head -4 | tail -2

3. git log | head -1 (if running from git repo)

4. openssl version used by testssl.sh: testssl.sh -b 2>/dev/null | awk -F':' '/openssl/ { print $2}'

5. steps to reproduce: testssl.sh or docker command line, if possible incl. host

6. what exactly was happening, output is needed

7. what did you expect instead?


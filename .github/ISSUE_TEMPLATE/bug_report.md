---
name: Bug report
about: Create a report to help us improve
title: "[BUG / possible BUG]"
labels: ''
assignees: ''

---
<!---

_Feel free to remove this line but please stick to the template. We would like to reproduce the bug and therefore need concise information. Depending on the completeness of your information provided we might close your issue otherwise. _
-->

**Before you open an issue please check this repo whether this is a known problem**
If in doubt check the git log and/or check whether you run the lastest version from the git repo.

**Command line / docker command to reproduce**
In addition the target of your scan would be helpful. If you don't want to disclose it publicly: ``grep SWCONTACT testssl.sh``.


**Expected behavior**
A clear and concise description of what you expected to happen.


**Your system (please complete the following information):**
 - OS: ``awk -F\" '/PRETTY_NAME/ { print $2 }' /etc/os-release``
 - Platform: ``uname -srm``
 - Version: ``testssl.sh -b 2>/dev/null | head -4 | tail -2``
 - Version if running from git repo: ``git log | head -1`` 
 - OpenSSL: ``testssl.sh -b 2>/dev/null | awk -F':' '/openssl/ { print $2}'``


**Additional context**
Add any other context about the problem here.

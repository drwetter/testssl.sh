---
name: Bug report
about: Create a report to help us improve
title: "[BUG / possible BUG]"
labels: ''
assignees: ''

---

_**Please just don't remove this template. We need to reproduce the bug and need concise information for that**_

**Command line / docker command to reproduce**

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

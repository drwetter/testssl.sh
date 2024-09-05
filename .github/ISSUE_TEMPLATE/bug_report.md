---
name: Bug report
about: Create a report to help us improve
title: "[BUG / possible BUG]"
labels: 'bug:to be reproduced,bug:needs triage/confirmation'
assignees: ''

---
<!---

_Feel free to remove this line but please stick to the template. We would like to reproduce the bug and therefore need concise information. Depending on the lack of information provided we might close your issue otherwise right away. _
-->

**Before you open an issue please check which version you are running and whether it is the latest in stable / dev branch**

I am running version (``git log | head -1`` if running from the git repo. Otherwise ``testssl.sh -v | grep from``)


**Before you open an issue please whether this is a known problem by searching the issues**

Is related to / couldn't find anything


**Command line / docker command to reproduce**

Which was your command line? In addition the target of your scan would be helpful. If you don't want to disclose it publicly: ``grep SWCONTACT testssl.sh``.


**Expected behavior**

A clear and concise description of what you would expect to happen.


**Your system (please complete the following information):**
 - OS: ``awk -F\" '/PRETTY_NAME/ { print $2 }' /etc/os-release``
 - Platform: ``uname -srm``
 - OpenSSL + bash: ``testssl.sh -b 2>/dev/null | grep Using '``

**Additional context**

Add any other context about the problem goes here.

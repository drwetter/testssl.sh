
#### Certificate stores

The certificate stores were retrieved by

* Mozilla; see https://curl.haxx.se/docs/caextract.html
* Linux: Just copied from an up-to-date Linux machine
* Microsoft: For Windows >= 7/2008 Microsoft decided not to provide
  a full certificate store by default or via update as all other OS do. 
  It's being populated with time -- supposed you use e.g. IE while browsing. 
  Thus this file is smaller as the others.
  This store was destilled from three different windows installations via 
  "certmgr.msc". It's a PKCS7 export of "Trusted Root Certification Authorities"
  and the Third Party Store.
  Feedback is welcome, see #317.
  It's still behind what MS publishes what [should be included](http://social.technet.microsoft.com/wiki/contents/articles/31634.microsoft-trusted-root-certificate-program-participants-v-2016-april.aspx).
  Unfortunately there doesn't seem to be store to DL. Let me know if
  you have a pointer
* Apple: It comes from Apple OS X keychain app.  Open Keychain Access.
  In the Finder window, under Favorites --> "Applications" --> "Utilities"
  --> "Keychain Access" (2 click). In that window --> "Keychains" --> "System"
  --> "Category" --> "All Items"
  Select all CA certificates,  "File" --> "Export Items"

In this directory you can also save e.g. your company Root CA(s) in PEM 
format, extension ``pem``. This has two catches momentarily: You will still 
get a warning for the other certificate stores while scanning internal net-
works.  Second catch: If you scan other hosts in the internet the check against 
your Root CA will fail, too. This will be fixed in the future, see #230.

#### Mapping files
The file ``mapping-rfc.txt`` uses the hexcode to map OpenSSL names
against the RFC/IANA names. ``curves.txt`` is not being used yet, it
is supposed to map EC curve names properly.


#### Certification stores

The certificate stores were retrieved by

* Mozilla; see https://curl.haxx.se/docs/caextract.html
* Linux: Just copied from an up-to-date Linux machine
* Microsoft: under Windows >= 7,2008 MS decided not to provide
  a full certificate store bu default/via update as other OS. 
  It's being populated with time -- supposed you use e.g. IE while browsing. 
  This store was destilled from three different windows installations via 
  certmgr.msc and is an export of  "Trusted Root Certification Authorities"  
  --> "Certificates". Third Party Root Certificates were for now deliberately 
  omitted. Feedback is welcome, see #317.

In this directory you can also save e.g. your company Root CA(s) in PEM 
format, extension ``pem``. This has two catches momentarily: You will still 
get a warning for  the other certificate storesthough while scanning internal 
networks.  If you scan other hosts in the internet the check against your 
Root CA will fail, too. This will be fixed in the future, see #230.

#### Mapping files
The file ``mapping-rfc.txt`` uses the hexcode to map OpenSSL names
against the RFC/IANA names. ``curves.txt`` is not being used yet, it
is supposed to map EC curve names properly.

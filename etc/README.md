
#### Certification stores

The certificate stores were retrieved by

* Mozilla; see https://curl.haxx.se/docs/caextract.html
* Linux: Just copied from a uptodate Linux machine
* Microsoft: under Windows >= 7,2008 MS decided not to provide
  a full certificate store. It's being populated with time --
  supposed you use e.g. IE while browsing. This store was destilled
  from three different windows installations via certmgr.msc and
  export of "Trusted Root Certification Authorities"  --> "Certificates".
  Third Party Root Certificates were deliberately omitted.

In this directory you can also save e.g. your company Root CAs in PEM 
format.  You will still get a warning for the other certificate stores 
though while scanning internal networks. If you scan other hosts in the 
internet the check against your Root CA will fail, too. This will be
fixed in the future, see #230.

#### Mapping file

The file mapping-rfc.txt uses the hexcode to map OpenSSL names
against the RFC/IAMA names

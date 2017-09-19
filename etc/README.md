
#### Certificate stores

The certificate stores were retrieved by

* Mozilla; see https://curl.haxx.se/docs/caextract.html
* Linux: Just copied from an up-to-date Linux machine
* Microsoft: Following command pulls all certificates from Windows Update services: (see also http://aka.ms/RootCertDownload, https://technet.microsoft.com/en-us/library/dn265983(v=ws.11).aspx#BKMK_CertUtilOptions):  ``CertUtil -syncWithWU -f -f . ``. 
* Apple: It comes from Apple OS X keychain app.  Open Keychain Access utility, i.e.
  In the Finder window, under Favorites --> "Applications" --> "Utilities" 
  (OR perform a Spotlight Search for Keychain Access)
  --> "Keychain Access" (2 click). In that window --> "Keychains" --> "System"
  --> "Category" --> "All Items"
  Select all CA certificates except for Developer ID Certification Authority,  "File" --> "Export Items"

In this directory you can also save e.g. your company Root CA(s) in PEM
format, extension ``pem``. This has two catches momentarily: You will still
get a warning for the other certificate stores while scanning internal net-
works.  Second catch: If you scan other hosts in the internet the check against
your Root CA will fail, too. This will be fixed in the future, see #230.

#### Further needed files
* ``tls_data.txt`` contains lists of cipher suites and private keys for sockets-based tests

* ``cipher-mapping.txt`` contains information about all of the cipher suites defined for SSL/TLS

* ``ca_hashes.txt`` is used for HPKP test in order to have a fast comparison with known CAs. Use
   ``~/utils/create_ca_hashes.sh`` for an update

* ``common-primes.txt`` is used for LOGJAM

* ``client-simulation.txt`` as the name indicates it's the data for the client simulation. Use
  ``~/utils/update_client_sim_data.pl`` for an update. Note: This list has been manually
  edited to sort it and weed it out.

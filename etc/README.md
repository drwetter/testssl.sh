
### Certificate stores

The certificate trust stores were retrieved from

* **Linux:** Copied from an up-to-date Debian Linux machine
* **Mozilla:** https://curl.haxx.se/docs/caextract.html
* **Java:** extracted (``keytool -list -rfc -keystore lib/security/cacerts | grep -E -v '^$|^\*\*\*\*\*|^Entry |^Creation |^Alias '``) from a JDK LTS version from https://jdk.java.net/. (use dos2unix).
* **Microsoft:** Following command pulls all certificates from Windows Update services: ``CertUtil -syncWithWU -f -f . `` (see also http://aka.ms/RootCertDownload, https://technet.microsoft.com/en-us/library/dn265983(v=ws.11).aspx#BKMK_CertUtilOptions). They are in DER format. Convert them like ``for f in *.cer; do echo $f >/dev/stderr; openssl x509 -in $f -inform DER -outform PEM ;done >/tmp/Microsoft.pem``
* **Apple:**
    1. __System:__ from Apple OS X keychain app.  Open Keychain Access utility, i.e.
  In the Finder window, under Favorites --> "Applications" --> "Utilities"
  (OR perform a Spotlight Search for "Keychain Access")
  --> "Keychain Access" (2 click). In that window --> "Keychains" --> "System Root"
  --> "Category" --> "All Items"
  Select all CA certificates except for "Developer ID Certification Authority", omit expired ones,  "File" --> "Export Items"
    2. __Internet:__ Pick the latest subdir (=highest number) from https://opensource.apple.com/source/security_certificates/. They are in all DER format despite their file extension. Download them with ``wget --level=1 --cut-dirs=5 --mirror --convert-links --adjust-extension --page-requisites --no-parent https://opensource.apple.com/source/security_certificates/security_certificates-<latest>/certificates/roots/``. Then: ``for f in *.cer *.der *.crt; do echo $f >/dev/stderr; openssl x509 -in $f -inform DER -outform PEM ;done >/tmp/Apple.pem``

**Attention**: You need to remove the DST Root CA X3 which is for your reference in this directory.

Google Chromium uses basically the trust stores above, see https://www.chromium.org/Home/chromium-security/root-ca-policy.

If you want to check trust against e.g. a company internal CA you need to use ``./testssl.sh --add-ca companyCA1.pem,companyCA2.pem <further_cmds>`` or ``ADDTL_CA_FILES=companyCA1.pem,companyCA2.pem ./testssl.sh <further_cmds>``.


#### Further files

* ``tls_data.txt`` contains lists of cipher suites and private keys for sockets-based tests

* ``cipher-mapping.txt`` contains information about all of the cipher suites defined for SSL/TLS

* ``curves-mapping.txt`` contains information about all of the elliptic curves defined by IANA

* ``ca_hashes.txt`` is used for HPKP test in order to have a fast comparison with known CAs. Use
   ``~/utils/create_ca_hashes.sh`` for an update

* ``common-primes.txt`` is used for LOGJAM and the PFS section

* ``client-simulation.txt`` / ``client-simulation.wiresharked.txt`` are as the names indicate data for the client simulation.
  The first one is derived from ``~/utils/update_client_sim_data.pl``, and manually edited to sort and label those we don't want.
  The second file provides more client data retrieved from wireshark captures and some instructions how to do that yourself.

* SSLSocketClient.java as the name indicates is a simple socket client in Java to generate a TLS/SSL handshake. It's taken from
  https://docs.oracle.com/javase/10/security/sample-code-illustrating-secure-socket-connection-client-and-server.htm . It's not
  ours and it's not GPLv2. There wasn't any license mentioned, it's only added for your convenience.

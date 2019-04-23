#### Features implemented in 2.9.5 (short version)

* Way better coverage of ciphers as most checks are done via bash sockets where ever possible
* Further tests via TLS sockets and improvements (handshake parsing, completeness, robustness)
* Testing 359 default ciphers (``testssl.sh -e/-E``) with a mixture of sockets and openssl. Same speed as with openssl only but addtional ciphers such as post-quantum ciphers, new CHAHA20/POLY1305, CamelliaGCM etc.
* TLS 1.2 protocol check via sockets in production
* Finding more TLS extensions via sockets
* TLS Supported Groups Registry (RFC 7919), key shares extension
* Non-flat JSON output support
* File output (CSV, JSON flat, JSON non-flat) supports a minimum severity level (only above supplied level there will be output)
* Native HTML support instead going through 'aha'
* LUCKY13 and SWEET32 checks
* Ticketbleed check
* LOGJAM: now checking also for known DH parameters
* Support of supplying timeout value for ``openssl connect`` -- useful for batch/mass scanning
* Parallel mass testing
* Check for CAA RR
* Check for OCSP must staple
* Check for Certificate Transparency
* Check for session resumption (Ticket, ID)
* Better formatting of output (indentation)
* Choice showing the RFC naming scheme only
* File input for mass testing can be also in nmap grep(p)able (-oG) format
* Postgres und MySQL STARTTLS support
* Man page

This file contains client handshake data manually created from Wireshark.
The content needs to be added to client-simulation.txt which other part
comes from the SSLlabs client API via ``update_client_sim_data.pl``
The whole process is done manually.

## Instructions how to add a client simulation:

* Start wireshark at a client or router. Best is during capture to filter for the target of your choice.
* Make sure you create a bit of encrypted traffic to your target. Attention, privacy: if you want to contribute, be aware that the ClientHello contains the target hostname (SNI).
* Make sure the client traffic is specific: For just "Android" do not use a browser! Be also careful with Google Apps, especially on older devices as they might come with an own/updated TLS stack
* Stop recording.
* If needed sort for ClientHello.
* Look for the ClientHello which matches the source IP + destination you had in mind. Check the destination hostname in the SNI extension so that you can be sure, it's the right traffic.
* Retrieve "handshakebytes" by marking the Record Layer --> Copy --> As a hex stream.
* Figure out "protos" and "tlsvers" by looking at the supported_versions TLS extension (43=0x002b). May work only on modern clients. Be careful as some do not list all TLS versions here (OpenSSL 1.1.1 lists only TLS 1.2/1.3 here)
* Adjust "lowest_protocol" and "highest_protocol" accordingly.
* Get "curves" from at the supported groups TLS extension 10 = 0x00a. Omit any GREASE.
* Retrieve "alpn" by looking at the alpn TLS extension 16 (=0x0010).
* Review TLS extension 13 (=0x000d) whether any SHA1 signature algorithm is listed. If not "requiresSha2" is true
* Leave "maxDhBits"/"minDhBits" and "minRsaBits"/"maxRsaBits" at -1, unless you know for sure what the client can handle
* For "ciphers" mark the cipher suites --> Copy --> As a hex stream, remove any leading GREASE ciphers (?a?a) and supply it to `~/utils/hexstream2cipher.sh`
* "ciphersutes" are TLS 1.3 ciphersuites. You can identify them as they currently are like 0x130?. Retrieve them from above see ``~/utils/hexstream2cipher.sh``
* Figure out the services by applying a good piece of human logic
* Before submitting a PR: test it yourself! You can also watch it again via wireshark





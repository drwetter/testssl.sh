The file `client-simulation.wiresharked.txt` contains client handshake data manually harvested from a network capture and displayed best with Wireshark.
The content needs to be added to `client-simulation.txt` which other part comes from the SSLlabs client API via `update_client_sim_data.pl`
The whole process is manual but not too difficult.

## Instructions how to add a client simulation:

* Start wireshark / tcpdump at a client or router. If it's too noisy better filter for the target of your choice.
* Make sure you create a bit of encrypted traffic to your target. Attention, privacy: if you want to contribute, be aware that the ClientHello contains the target hostname (SNI).
* Make sure the client traffic is specific: For just "Android" do not use an Android browser! Be also careful with factory installed Google Apps, especially on older devices as they might come with a different TLS stack.
* Stop recording.
* If needed sort for ClientHello.
* Look for the ClientHello which matches the source IP + destination you had in mind. Check the destination hostname in the SNI extension so that you can be sure, it's the right traffic.
* Edit `client-simulation.wiresharked.txt` and insert a new section, preferably by copying a previous version of the client from it.
* Edit the *names* accordingly and *short*. The latter must not contain blanks.
* Retrieve *handshakebytes* by marking the "TLS 1.x Record Layer" --> Copy --> As a hex stream.
* For *ch_ciphers* mark "Cipher Suites" --> Copy --> As a hex stream, remove any leading GREASE ciphers (?a?a) and supply it to `~/utils/hexstream2cipher.sh`. For consistency reasons it is preferred you remove the TLS 1.3 ciphers before which start with TLS\*.
* *ciphersuites* are TLS 1.3 ciphersuites. You can identify them as they currently are like 0x130?. Retrieve them from above see `~/utils/hexstream2cipher.sh`. They start with TLS\*.
* Figure out *protos* and *tlsvers* by looking at the *supported_versions* TLS extension (43=0x002b). May work only with recent clients. Be careful as some do not list all TLS versions here (OpenSSL 1.1.1 listed only TLS 1.2/1.3).
* Adjust *lowest_protocol* and *highest_protocol* accordingly.
* For *curves* mark the "supported groups" TLS extension --> Copy --> As a hex stream, remove any leading GREASE ciphers (?a?a) and supply it to `~/utils/hexstream2curves.sh`.
* Retrieve *alpn* by looking at the "alpn" TLS extension 16 (=0x0010).
* Review TLS extension 13 (=0x000d) "signature_algorithm" whether any SHA1 signature algorithm is listed. If not *requiresSha2* is true.
* Leave *maxDhBits*/*minDhBits* and *minRsaBits*/*maxRsaBit* at -1, unless you know for sure what the client can handle.
* Figure out the *services* by applying a good piece of human logic. A (modern) browser is probably "HTTP", OpenSSL or Java "ANY"  whereas Thunderbird supports a variety of protocols.
* When you're done copy your inserted section from `client-simulation.wiresharked.txt` into `client-simulation.txt`.
* Before submitting a PR: test it yourself! You can also watch it again via wireshark.

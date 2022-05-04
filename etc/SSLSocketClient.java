import java.net.*;
import java.io.*;
import javax.net.ssl.*;

/*  java SSLSocketClient taken from
 *  https://docs.oracle.com/javase/10/security/sample-code-illustrating-secure-socket-connection-client-and-server.htm
 *  License: Unknown, not GPLv2
 */

/*
 * This example demonstrates how to use a SSLSocket as client to
 * send a HTTP request and get response from an HTTPS server.
 * It assumes that the client is not behind a firewall.
 * The handshake doesn't include any ALPN protocols. See
 * https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/alpn.html
 * for more documentation.
 */

public class SSLSocketClient {

    public static void main(String[] args) throws Exception {
        String host=args[0];

        if ( args == null || args.length == 0 || host.trim().isEmpty() ) {
            System.out.println("You need to supply a valid hostname");
        } else {
            try {
                SSLSocketFactory factory =
                    (SSLSocketFactory)SSLSocketFactory.getDefault();
                SSLSocket socket =
                    (SSLSocket)factory.createSocket(host, 443);

                /*
                * send http request
                *
                * Before any application data is sent or received, the
                * SSL socket will do SSL handshaking first to set up
                * the security attributes.
                *
                * SSL handshaking can be initiated by either flushing data
                * down the pipe, or by starting the handshaking by hand.
                *
                * Handshaking is started manually in this example because
                * PrintWriter catches all IOExceptions (including
                * SSLExceptions), sets an internal error flag, and then
                * returns without rethrowing the exception.
                *
                * Unfortunately, this means any error messages are lost,
                * which caused lots of confusion for others using this
                * code.  The only way to tell there was an error is to call
                * PrintWriter.checkError().
                */
                socket.startHandshake();

                PrintWriter out = new PrintWriter(
                                    new BufferedWriter(
                                    new OutputStreamWriter(
                                    socket.getOutputStream())));

                out.println("GET / HTTP/1.1");
                out.println("Host: " + host);
                out.println("Connection: close");
                out.println();
                out.flush();

                /*
                * Make sure there were no surprises
                */
                if (out.checkError())
                    System.out.println(
                        "SSLSocketClient:  java.io.PrintWriter error");

                /* read response */
                BufferedReader in = new BufferedReader(
                                        new InputStreamReader(
                                        socket.getInputStream()));

                String inputLine;
                while ((inputLine = in.readLine()) != null)
                    System.out.println(inputLine);

                in.close();
                out.close();
                socket.close();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}

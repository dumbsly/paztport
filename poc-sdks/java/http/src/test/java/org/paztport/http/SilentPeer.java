// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A peer that takes every connection on a loopback port and then stops: with no answer at all, or, if asked, with
 * a response's headers and the first bytes of a body it never finishes. It keeps each connection open until it is
 * closed, so a client waiting on it waits until its own timeout ends the call, or for ever.
 */
public final class SilentPeer implements AutoCloseable {

    /** What the peer sends before it stops. */
    public enum Stall {
        /** Nothing: the request is read and never answered. */
        BEFORE_HEADERS,
        /** A 200's headers, promising a 100-byte body, and three bytes of it. */
        AFTER_HEADERS
    }

    private static final byte[] HEADERS_THEN_PART_OF_A_BODY =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"o"
                    .getBytes(StandardCharsets.US_ASCII);

    private final ServerSocket server;
    private final Stall stall;
    private final List<Socket> accepted = new CopyOnWriteArrayList<>();

    public SilentPeer(Stall stall) throws IOException {
        this.stall = stall;
        this.server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread acceptor = new Thread(this::accept, "silent-peer");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    /** {@code http://127.0.0.1:<port>}. */
    public String url() {
        return "http://127.0.0.1:" + server.getLocalPort();
    }

    /** How many connections it has taken. */
    public int connections() {
        return accepted.size();
    }

    private void accept() {
        while (!server.isClosed()) {
            try {
                Socket socket = server.accept();
                accepted.add(socket);
                Thread reader = new Thread(() -> answer(socket), "silent-peer-connection");
                reader.setDaemon(true);
                reader.start();
            } catch (IOException e) {
                return;
            }
        }
    }

    /** Reads the request head, sends what the stall allows, then reads (and drops) whatever comes until the end. */
    private void answer(Socket socket) {
        try (socket) {
            InputStream in = socket.getInputStream();
            readHead(in);
            if (stall == Stall.AFTER_HEADERS) {
                socket.getOutputStream().write(HEADERS_THEN_PART_OF_A_BODY);
                socket.getOutputStream().flush();
            }
            byte[] drop = new byte[8192];
            while (in.read(drop) != -1) {
                // The request's body, then nothing until the client gives up and closes.
            }
        } catch (SocketException e) {
            // Closed by the client or by close().
        } catch (IOException e) {
            // Nothing to do: the peer only ever goes quiet.
        }
    }

    private static void readHead(InputStream in) throws IOException {
        int matched = 0;
        byte[] end = {'\r', '\n', '\r', '\n'};
        int b;
        while (matched < end.length && (b = in.read()) != -1) {
            matched = b == end[matched] ? matched + 1 : (b == '\r' ? 1 : 0);
        }
    }

    @Override
    public void close() throws IOException {
        server.close();
        for (Socket socket : accepted) {
            socket.close();
        }
    }
}

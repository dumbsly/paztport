// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.demo.drain;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.io.PrintWriter;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Sets {@code Connection: close} on every response while the service drains. A request already in progress when the
 * drain begins gets the header too: the response is also marked at each point where it can be committed, and again
 * when the chain returns if it has not been committed by then. Tomcat closes the connection after such a response.
 */
public final class ConnectionCloseFilter extends OncePerRequestFilter {

    private final DrainState state;

    public ConnectionCloseFilter(DrainState state) {
        this.state = state;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Marking marked = new Marking(response, state);
        marked.markIfDraining();
        try {
            chain.doFilter(request, marked);
        } finally {
            if (!response.isCommitted()) {
                marked.markIfDraining();
            }
        }
    }

    /** The response, marked as it is about to be committed. */
    private static final class Marking extends HttpServletResponseWrapper {

        private final DrainState state;

        Marking(HttpServletResponse response, DrainState state) {
            super(response);
            this.state = state;
        }

        void markIfDraining() {
            if (state.draining() && !isCommitted()) {
                setHeader("Connection", "close");
            }
        }

        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            markIfDraining();
            return super.getOutputStream();
        }

        @Override
        public PrintWriter getWriter() throws IOException {
            markIfDraining();
            return super.getWriter();
        }

        @Override
        public void flushBuffer() throws IOException {
            markIfDraining();
            super.flushBuffer();
        }

        @Override
        public void sendError(int status) throws IOException {
            markIfDraining();
            super.sendError(status);
        }

        @Override
        public void sendError(int status, String message) throws IOException {
            markIfDraining();
            super.sendError(status, message);
        }

        @Override
        public void sendRedirect(String location, int status, boolean clearBuffer) throws IOException {
            markIfDraining();
            super.sendRedirect(location, status, clearBuffer);
        }
    }
}

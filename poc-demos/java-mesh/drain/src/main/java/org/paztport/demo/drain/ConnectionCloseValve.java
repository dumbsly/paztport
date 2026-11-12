// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.demo.drain;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.io.PrintWriter;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;

/**
 * Sets {@code Connection: close} on every response while the service drains. It sits in Tomcat's pipeline and
 * replaces the response the servlet filter chain sees, so it is outside every filter: a response written by a filter
 * that refuses a request itself is marked as well as one from the handler. A request already in progress when the
 * drain begins is marked too: the response is also marked at each point where it can be committed, and again when
 * the chain returns if it has not been committed by then. Tomcat closes the connection after such a response.
 */
final class ConnectionCloseValve extends ValveBase {

    private final DrainState state;

    ConnectionCloseValve(DrainState state) {
        this.state = state;
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        Marking marking = new Marking(response.getResponse(), state);
        response.setResponse(marking);
        marking.markIfDraining();
        try {
            getNext().invoke(request, response);
        } finally {
            marking.markIfDraining();
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

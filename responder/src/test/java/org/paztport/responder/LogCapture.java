// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import org.slf4j.LoggerFactory;

/** Collects one logger's formatted lines; the test logback config otherwise silences everything. */
final class LogCapture implements AutoCloseable {

    private final Logger logger;
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    LogCapture(Class<?> source) {
        logger = (Logger) LoggerFactory.getLogger(source);
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.ALL);
    }

    List<String> lines() {
        return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    @Override
    public void close() {
        logger.detachAppender(appender);
        logger.setLevel(null);
    }
}

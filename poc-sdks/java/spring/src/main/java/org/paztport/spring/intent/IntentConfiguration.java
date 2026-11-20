// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.intent;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.paztport.core.intent.Intent;
import org.paztport.core.stamp.Block;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.http.OriginIntent;
import org.paztport.spring.PaztportAutoConfiguration;
import org.paztport.spring.PaztportProperties;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.handler.MappedInterceptor;
import org.springframework.web.servlet.mvc.method.RequestMappingInfoHandlerMapping;

/**
 * The extension {@code intent} at a receiver (spec intent.md, The receiver's part): the {@link OriginIntent} a
 * handler reads the origin's facts from, the check that refuses a request missing a fact a handler requires
 * ({@link IntentCheck}), and the check, once every handler mapping is known, that the annotations can be acted on.
 * The item check, which refuses items that do not read, is the receiver's, on every request of a service that acts on
 * {@code intent}.
 *
 * <p>The context does not start, naming the handler, where a handler method is annotated {@link RequiresIntent} and
 * {@code paztport.extensions.acts-on} does not hold {@code intent}, since such a service is handed no facts and would
 * refuse every request; where the annotation names no fact; or where a name is not a fact name.
 *
 * <p>{@link PaztportAutoConfiguration} imports it; it is not for an application to use directly.
 */
@Configuration(proxyBeanMethods = false)
public class IntentConfiguration {

    /** Always present: it needs no keys, only this service's name for its trace line. */
    @Bean
    OriginIntent paztportOriginIntent(PaztportProperties props) {
        return new OriginIntent(props.getServiceName());
    }

    /**
     * The check, as an annotated handler is about to run, that the facts it requires were stated ({@link IntentCheck}),
     * on every service. It is a {@link MappedInterceptor} bean with no path patterns, so every handler mapping in the
     * context picks it up and runs it ahead of the interceptors a {@code WebMvcConfigurer} registers, and ahead of
     * Paztport's last interceptor, so a request it refuses is never marked reached. A mapping runs such beans in the
     * order their definitions were registered; {@link PaztportAutoConfiguration} imports this configuration after
     * the operations' so that the dispatch check runs first, where there is one.
     */
    @Bean
    MappedInterceptor paztportIntentCheck(OriginIntent intent) {
        return new MappedInterceptor(null, new IntentCheck(intent));
    }

    /**
     * Once every singleton is created, so every handler mapping is known, refuses an annotated handler on a service
     * that does not act on {@code intent}, or whose annotation names no fact or a name that is not a fact name.
     */
    @Bean
    SmartInitializingSingleton paztportIntentHandlers(ExtensionSettings extensions, ListableBeanFactory beans) {
        return () -> requireActable(annotated(beans), extensions);
    }

    /**
     * The handler methods of every annotated handler mapping in the context and its ancestors that carry
     * {@link RequiresIntent}, by {@code beanType#method}, sorted, so a refusal names the same handler on every start.
     */
    static List<Annotated> annotated(ListableBeanFactory beans) {
        List<Annotated> found = new ArrayList<>();
        for (HandlerMapping mapping
                : BeanFactoryUtils.beansOfTypeIncludingAncestors(beans, HandlerMapping.class, true, false).values()) {
            if (!(mapping instanceof RequestMappingInfoHandlerMapping handlers)) {
                continue;
            }
            for (HandlerMethod handler : handlers.getHandlerMethods().values()) {
                RequiresIntent requires = handler.getMethodAnnotation(RequiresIntent.class);
                if (requires != null) {
                    found.add(new Annotated(handler.getBeanType().getName() + "#" + handler.getMethod().getName(),
                            List.of(requires.value())));
                }
            }
        }
        found.sort(Comparator.comparing(Annotated::handler));
        return found;
    }

    /**
     * Refuses the first of {@code annotated} that cannot be acted on: any, where {@code extensions} does not act on
     * {@code intent}; one that names no fact; one with a name that is not a fact name.
     *
     * @throws IllegalStateException naming the handler
     */
    static void requireActable(List<Annotated> annotated, ExtensionSettings extensions) {
        for (Annotated handler : annotated) {
            if (!extensions.actsOn().contains(Intent.NAME)) {
                throw new IllegalStateException("the handler " + handler.handler() + " is annotated @RequiresIntent, "
                        + "but paztport.extensions.acts-on does not hold intent, so this service is handed no facts "
                        + "and would refuse every request to it; add intent to paztport.extensions.acts-on");
            }
            if (handler.names().isEmpty()) {
                throw new IllegalStateException("the handler " + handler.handler() + " is annotated @RequiresIntent "
                        + "but names no fact; name the facts it compares, or remove the annotation");
            }
            for (String name : handler.names()) {
                if (!Block.isExtensionName(name)) {
                    throw new IllegalStateException("the handler " + handler.handler() + " requires a name that is "
                            + "not a fact name, which is 1 to 32 of a-z, 0-9 and -");
                }
            }
        }
    }

    /** A handler method annotated {@link RequiresIntent}: {@code beanType#method}, and the names it requires. */
    record Annotated(String handler, List<String> names) {
    }
}

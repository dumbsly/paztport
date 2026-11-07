// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.operation;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.paztport.core.policy.OperationTable;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.filter.HiddenHttpMethodFilter;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.RequestMappingInfoHandlerMapping;
import org.springframework.web.util.ServletRequestPathUtils;

/**
 * This service's operation for a request: the one its own table holds for the request's method and the pattern of
 * the handler the {@link DispatcherServlet} will dispatch the request to. The inbound filter runs before the
 * DispatcherServlet has mapped the request, so this asks the same handler mappings, in the same order, as it will:
 * every {@link HandlerMapping} bean, sorted by order, the first that answers a handler deciding. The pattern is the
 * one that mapping sets as {@link HandlerMapping#BEST_MATCHING_PATTERN_ATTRIBUTE}, which the handler's interceptors
 * read too. The operation is never found by matching the path against the table, so a path that Spring and a caller
 * match differently (a regex variable, a trailing slash, a percent-encoded segment) is confirmed as the operation
 * Spring will actually run, or as none, and a chain naming the caller's choice is refused.
 *
 * <p>Spring's {@code HandlerMappingIntrospector}, which asked the mappings in this way for a filter, is deprecated for
 * removal as of Spring Framework 7, so this asks them itself. Where a mapping fails the request (a method or a media
 * type its handlers do not take) the DispatcherServlet answers an error and runs no handler, and there is no
 * operation; unlike the introspector, this does not go on to the next mapping, as the DispatcherServlet does not.
 *
 * <p>A pattern normalises to a template ({@link #template}) when each of its segments is literal text or one whole
 * variable, which becomes {@code {}}, a regex variable such as {@code {id:\d+}} included. A pattern with a wildcard,
 * a variable that captures the rest of the path, or a segment that mixes literal text and a variable normalises to
 * none, so the request has no operation.
 *
 * <p>Once every singleton is created, so every handler mapping is known, it checks the table: each of its operations
 * must be an annotated handler mapping, a method (or none, which takes every method) and a pattern that normalises
 * to the operation's template, or the context does not start. A mapping that is in no table is allowed: it is
 * reachable only by routes that name no operation. Nor does the context start beside a {@link HiddenHttpMethodFilter},
 * which changes the request's method after the inbound filter has confirmed the operation for the method sent.
 */
public final class OperationResolver implements SmartInitializingSingleton {

    private final OperationTable table;
    private final ListableBeanFactory beans;
    private volatile List<HandlerMapping> mappings = List.of();

    /**
     * @param table this service's own table, covered by the signed root
     * @param beans where the handler mappings are found once every singleton is created
     */
    public OperationResolver(OperationTable table, ListableBeanFactory beans) {
        this.table = Objects.requireNonNull(table, "table");
        this.beans = Objects.requireNonNull(beans, "beans");
    }

    /**
     * Finds the handler mappings as the DispatcherServlet finds them, every one in the context and its ancestors,
     * in their order, and refuses a table operation that none of them maps, or a method-override filter.
     */
    @Override
    public void afterSingletonsInstantiated() {
        requireNoMethodOverride(beans);
        List<HandlerMapping> found = new ArrayList<>(
                BeanFactoryUtils.beansOfTypeIncludingAncestors(beans, HandlerMapping.class, true, false).values());
        AnnotationAwareOrderComparator.sort(found);
        requireMapped(table, found);
        mappings = List.copyOf(found);
    }

    /**
     * The name of the operation in this service's table for the request's method and the pattern of the handler it
     * will be dispatched to, or null when it will be dispatched to none, or to one whose pattern normalises to no
     * template or to a template the table has no operation at for that method. The request's attributes are as they
     * were afterwards.
     */
    public String operationFor(HttpServletRequest request) {
        String template = template(patternFor(request));
        return template == null ? null : table.operationFor(request.getMethod(), template);
    }

    /**
     * The pattern the DispatcherServlet's handler mapping sets for the request as it maps it, or null when no mapping
     * will answer a handler, or the one that will sets no pattern as it maps. Annotated handlers' and router
     * functions' mappings set it then; a URL-mapped handler's, such as static resources', sets it only as the handler
     * is about to run, so a request for one has no pattern here and no operation. The mappings run against a wrapper
     * that keeps every attribute they set or remove to itself, so nothing they leave reaches the request; the request
     * path is parsed into it, as the DispatcherServlet parses it before it asks the mappings.
     */
    String patternFor(HttpServletRequest request) {
        Probe probe = new Probe(request);
        ServletRequestPathUtils.parseAndCache(probe);
        try {
            for (HandlerMapping mapping : mappings) {
                if (mapping.getHandler(probe) != null) {
                    return probe.set(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE) instanceof String p ? p : null;
                }
            }
        } catch (Exception e) {
            // The DispatcherServlet fails the request here too, with an error and no handler.
        }
        return null;
    }

    /**
     * The template {@code pattern} normalises to, or null for none: each whole-segment variable becomes {@code {}},
     * and each literal segment stays as it is. A pattern that is not absolute, has an empty segment, or has a segment
     * with a wildcard ({@code *}, {@code **}, {@code ?}), a variable that captures the rest of the path
     * ({@code {*rest}}), or literal text and a variable together, has none.
     */
    static String template(String pattern) {
        if (pattern == null || !pattern.startsWith("/")) {
            return null;
        }
        if (pattern.equals("/")) {
            return pattern;
        }
        StringBuilder template = new StringBuilder();
        for (String segment : pattern.substring(1).split("/", -1)) {
            template.append('/');
            if (wholeVariable(segment)) {
                if (segment.startsWith("{*")) {
                    return null;
                }
                template.append("{}");
            } else if (segment.isEmpty() || segment.chars().anyMatch(c -> "{}*?".indexOf(c) >= 0)) {
                return null;
            } else {
                template.append(segment);
            }
        }
        return template.toString();
    }

    /** Whether {@code segment} is one variable: its opening brace is closed by its last character and no sooner. */
    private static boolean wholeVariable(String segment) {
        if (segment.length() < 2 || segment.charAt(0) != '{') {
            return false;
        }
        int depth = 0;
        for (int i = 0; i < segment.length(); i++) {
            char c = segment.charAt(i);
            if (c == '{') {
                depth++;
            } else if (c == '}' && --depth == 0) {
                return i == segment.length() - 1;
            }
        }
        return false;
    }

    /**
     * Refuses a {@link HiddenHttpMethodFilter} bean, Boot's included ({@code spring.mvc.hiddenmethod.filter.enabled}):
     * it runs after the inbound filter and takes the request's method from its {@code _method} parameter, so a chain
     * confirmed for {@code POST /x}'s operation could run the handler of {@code DELETE /x}.
     */
    static void requireNoMethodOverride(ListableBeanFactory beans) {
        String[] names = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(beans, HiddenHttpMethodFilter.class,
                true, false);
        if (names.length > 0) {
            throw new IllegalStateException("paztport.operations.table-path: the bean " + names[0] + " is a "
                    + "HiddenHttpMethodFilter, which changes the request's method after Paztport's filter has "
                    + "confirmed the operation for the method sent; turn it off "
                    + "(spring.mvc.hiddenmethod.filter.enabled=false) or remove it");
        }
    }

    /** Refuses the first operation of {@code table} that no annotated handler maps. */
    static void requireMapped(OperationTable table, List<HandlerMapping> mappings) {
        Set<String> mapped = new HashSet<>();
        for (HandlerMapping mapping : mappings) {
            if (mapping instanceof RequestMappingInfoHandlerMapping annotated) {
                for (RequestMappingInfo info : annotated.getHandlerMethods().keySet()) {
                    Set<RequestMethod> methods = info.getMethodsCondition().getMethods();
                    for (String pattern : info.getPatternValues()) {
                        String template = template(pattern);
                        if (template == null) {
                            continue;
                        }
                        if (methods.isEmpty()) {
                            mapped.add("* " + template);
                        }
                        for (RequestMethod method : methods) {
                            mapped.add(method.name() + " " + template);
                        }
                    }
                }
            }
        }
        for (OperationTable.Operation op : table.operations()) {
            if (!mapped.contains(op.method() + " " + op.template()) && !mapped.contains("* " + op.template())) {
                throw new IllegalStateException("paztport.operations.table-path: the operation " + op.name() + ", "
                        + op.method() + " " + op.template() + ", is not a handler mapping of this service; no handler "
                        + "maps that method and a pattern that normalises to that template");
            }
        }
    }

    /**
     * The request as the handler mappings see it, keeping to itself each attribute they set or remove, so the
     * request's own attributes are as they were afterwards. A removed attribute is held as null.
     */
    private static final class Probe extends HttpServletRequestWrapper {

        private final Map<String, Object> attributes = new HashMap<>();

        Probe(HttpServletRequest request) {
            super(request);
        }

        /** What the mappings set as {@code name}, or null when they set nothing or removed it. */
        Object set(String name) {
            return attributes.get(name);
        }

        @Override
        public Object getAttribute(String name) {
            return attributes.containsKey(name) ? attributes.get(name) : super.getAttribute(name);
        }

        @Override
        public Enumeration<String> getAttributeNames() {
            Set<String> names = new LinkedHashSet<>(Collections.list(super.getAttributeNames()));
            attributes.forEach((name, value) -> {
                if (value == null) {
                    names.remove(name);
                } else {
                    names.add(name);
                }
            });
            return Collections.enumeration(names);
        }

        @Override
        public void setAttribute(String name, Object value) {
            attributes.put(name, value);
        }

        @Override
        public void removeAttribute(String name) {
            attributes.put(name, null);
        }
    }
}

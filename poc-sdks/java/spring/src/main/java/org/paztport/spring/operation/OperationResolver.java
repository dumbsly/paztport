// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.operation;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.paztport.core.policy.OperationTable;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.filter.HiddenHttpMethodFilter;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.mvc.condition.NameValueExpression;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.RequestMappingInfoHandlerMapping;
import org.springframework.web.util.ServletRequestPathUtils;

/**
 * This service's operation for a request: the operation in its own table that the handler the
 * {@link DispatcherServlet} will dispatch the request to is, for the request's method and the template of the
 * handler's pattern. An operation is a handler, so of one entrance's operations, which share a method and a template,
 * the one a request has is the handler Spring's routing picks by its {@code params} condition, never one found by
 * matching the request against the table. The inbound filter runs before the DispatcherServlet has mapped the
 * request, so this asks the same handler mappings, in the same order, as it will: every {@link HandlerMapping} bean,
 * sorted by order, the first that answers a handler deciding. The pattern is the one that mapping sets as
 * {@link HandlerMapping#BEST_MATCHING_PATTERN_ATTRIBUTE}, which the handler's interceptors read too. So a request that
 * Spring and a caller read differently (a regex variable, a trailing slash, a percent-encoded segment or query value)
 * is confirmed as the operation Spring will actually run, or as none, and a chain naming the caller's choice is
 * refused.
 *
 * <p>A service routes by method, path and query alone, and a request whose routing a body field changes is refused.
 * The inbound filter reads the body to bind it before anything parses it, so on a {@code POST} the container never
 * adds a form body's fields to the parameters: the query alone decides, and the handler named runs. On a {@code PUT},
 * {@code PATCH} or {@code DELETE}, Boot's form content filter, which runs after the inbound filter, adds them, so a
 * form body that meets a {@code params} condition makes the DispatcherServlet choose another handler than the one
 * this named, and the check made as that handler is about to run ({@link DispatchCheck}) refuses the request under
 * {@code enforce}, and elsewhere serves it unattested.
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
 * <p>Once every singleton is created, so every handler mapping is known, it checks the table against the annotated
 * handler mappings, each a method (or none, which takes every method), patterns and a {@code params} condition, and
 * learns from them which operation each handler is ({@link #operationsOf}). A mapping on a table entrance is that
 * entrance's operation whose query condition is the mapping's {@code params} condition, one non-negated
 * {@code name=value}, or the operation with none where the mapping has no {@code params} condition. The context does
 * not start where a mapping on a table entrance has a {@code params} condition that is none of the entrance's, or
 * where an operation is no handler or more than one, as two handlers that the entrance tells apart by headers, media
 * types or a regex are, or where one handler is more than one of an entrance's operations. Two beans that inherit one
 * handler method are two handlers. A mapping that is on no table entrance is allowed: it is reachable only by routes
 * that name no operation. Any other handler, a router function's or a URL-mapped one's, is no operation. Nor does
 * the context start beside a {@link HiddenHttpMethodFilter}, which changes the request's method after the inbound
 * filter has confirmed the operation for the method sent. Any other filter that changes the method, the path or the
 * parameters after the inbound filter is caught as the handler is about to run ({@link DispatchCheck}), which asks
 * this for the operation of the handler the DispatcherServlet chose.
 */
public final class OperationResolver implements SmartInitializingSingleton {

    private final OperationTable table;
    private final ListableBeanFactory beans;
    private volatile List<HandlerMapping> mappings = List.of();
    private volatile Map<Served, String> operations = Map.of();

    /**
     * Where a handler is served: its bean's type and its Java method, which both stay the same in the copy of the
     * handler a mapping answers for each request with its bean resolved, an HTTP method and a template.
     */
    record Served(Class<?> beanType, Method handler, String method, String template) {

        /** {@code beanType#name}, the handler as a refusal names it. */
        String describe() {
            return beanType.getName() + "#" + handler.getName();
        }
    }

    /** A handler as it is told apart from another: its bean's type and its Java method. */
    private record Handler(Class<?> beanType, Method method) {
    }

    /** The handler a request will be dispatched to, and the pattern its mapping sets, either null for none. */
    private record Dispatched(Object handler, String pattern) {
    }

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
     * in their order, learns which operation each handler is, and refuses a table its handlers do not serve one to
     * one ({@link #operationsOf}), or a method-override filter.
     */
    @Override
    public void afterSingletonsInstantiated() {
        requireNoMethodOverride(beans);
        List<HandlerMapping> found = new ArrayList<>(
                BeanFactoryUtils.beansOfTypeIncludingAncestors(beans, HandlerMapping.class, true, false).values());
        AnnotationAwareOrderComparator.sort(found);
        operations = Map.copyOf(operationsOf(table, found));
        mappings = List.copyOf(found);
    }

    /**
     * The name of the operation in this service's table that the handler the request will be dispatched to is, for
     * the request's method and the template of the handler's pattern, or null when it will be dispatched to none, or
     * to a handler that is no operation of the table ({@link #operationOf}). The request's attributes are as they
     * were afterwards.
     */
    public String operationFor(HttpServletRequest request) {
        Dispatched dispatched = dispatch(request);
        return operationOf(dispatched.handler(), request.getMethod(), dispatched.pattern());
    }

    /**
     * The name of the operation in this service's table that {@code handler} is when it serves {@code method} at
     * {@code pattern}, or null when the handler is not an annotated one, the pattern is null or normalises to no
     * template, or the handler is no operation there.
     */
    String operationOf(Object handler, String method, String pattern) {
        String template = template(pattern);
        if (!(handler instanceof HandlerMethod annotated) || template == null) {
            return null;
        }
        return operations.get(new Served(annotated.getBeanType(), annotated.getMethod(), method, template));
    }

    /**
     * The pattern the DispatcherServlet's handler mapping sets for the request as it maps it, or null when no mapping
     * will answer a handler, or the one that will sets no pattern as it maps ({@link #dispatch}).
     */
    String patternFor(HttpServletRequest request) {
        return dispatch(request).pattern();
    }

    /**
     * The handler the DispatcherServlet's handler mappings will answer for the request, and the pattern the one that
     * answers sets as it maps it; both null when none will answer. Annotated handlers' and router functions' mappings
     * set the pattern then; a URL-mapped handler's, such as static resources', sets it only as the handler is about to
     * run, so a request for one has no pattern here. The mappings run against a wrapper that keeps every attribute
     * they set or remove to itself, so nothing they leave reaches the request; the request path is parsed into it, as
     * the DispatcherServlet parses it before it asks the mappings.
     */
    private Dispatched dispatch(HttpServletRequest request) {
        Probe probe = new Probe(request);
        ServletRequestPathUtils.parseAndCache(probe);
        try {
            for (HandlerMapping mapping : mappings) {
                HandlerExecutionChain chain = mapping.getHandler(probe);
                if (chain != null) {
                    return new Dispatched(chain.getHandler(),
                            probe.set(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE) instanceof String p ? p : null);
                }
            }
        } catch (Exception e) {
            // The DispatcherServlet fails the request here too, with an error and no handler.
        }
        return new Dispatched(null, null);
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

    /**
     * The operation each annotated handler of {@code mappings} is where it serves one of {@code table}'s entrances,
     * by its bean's type, its Java method, the HTTP method and the template; refusing a mapping on a table entrance
     * whose {@code params} condition is none of the entrance's query conditions, a handler that is more than one
     * operation of an entrance, and an operation that no handler is, or more than one. A mapping with no method
     * condition serves each of the table's methods at its templates; one whose pattern normalises to no template, or
     * that is on no table entrance, is no operation. Handlers are told apart by their bean's type as well as their
     * Java method, so two beans that inherit one handler method from a base class are two handlers, as each class's
     * own mapping conditions may route a request to one and not the other. Where more than one refusal applies, the
     * one reported is the same on every start: the entrances and operations are checked in table order, and handlers
     * by name.
     */
    static Map<Served, String> operationsOf(OperationTable table, List<HandlerMapping> mappings) {
        Map<String, List<OperationTable.Operation>> entrances = new LinkedHashMap<>();
        Map<String, Set<String>> methodsAt = new HashMap<>();
        for (OperationTable.Operation op : table.operations()) {
            entrances.computeIfAbsent(op.method() + " " + op.template(), k -> new ArrayList<>()).add(op);
            methodsAt.computeIfAbsent(op.template(), k -> new LinkedHashSet<>()).add(op.method());
        }
        Map<Served, String> operations = new HashMap<>();
        Map<Served, Set<String>> named = new HashMap<>();
        Map<String, Map<Handler, HandlerMethod>> handlers = new HashMap<>();
        Map<String, TreeMap<String, String>> unheld = new HashMap<>();
        for (HandlerMapping mapping : mappings) {
            if (!(mapping instanceof RequestMappingInfoHandlerMapping annotated)) {
                continue;
            }
            for (Map.Entry<RequestMappingInfo, HandlerMethod> mapped : annotated.getHandlerMethods().entrySet()) {
                RequestMappingInfo info = mapped.getKey();
                HandlerMethod handler = mapped.getValue();
                Set<RequestMethod> declared = info.getMethodsCondition().getMethods();
                for (String pattern : info.getPatternValues()) {
                    String template = template(pattern);
                    if (template == null) {
                        continue;
                    }
                    Collection<String> methods = declared.isEmpty() ? methodsAt.getOrDefault(template, Set.of())
                            : declared.stream().map(RequestMethod::name).toList();
                    for (String method : methods) {
                        String entrance = method + " " + template;
                        List<OperationTable.Operation> of = entrances.get(entrance);
                        if (of == null) {
                            continue;
                        }
                        String name = expressible(info) ? table.operationFor(method, template, conditionOf(info))
                                : null;
                        if (name == null) {
                            unheld.computeIfAbsent(entrance, k -> new TreeMap<>()).put(handler.toString(),
                                    unheldCondition(of, info, handler, entrance));
                            continue;
                        }
                        handlers.computeIfAbsent(name, k -> new LinkedHashMap<>())
                                .put(new Handler(handler.getBeanType(), handler.getMethod()), handler);
                        Served served = new Served(handler.getBeanType(), handler.getMethod(), method, template);
                        named.computeIfAbsent(served, k -> new TreeSet<>()).add(name);
                        operations.put(served, name);
                    }
                }
            }
        }
        for (String entrance : entrances.keySet()) {
            TreeMap<String, String> refusals = unheld.get(entrance);
            if (refusals != null) {
                throw new IllegalStateException(refusals.firstEntry().getValue());
            }
        }
        for (String entrance : entrances.keySet()) {
            named.entrySet().stream()
                    .filter(e -> e.getValue().size() > 1
                            && entrance.equals(e.getKey().method() + " " + e.getKey().template()))
                    .min(Comparator.comparing((Map.Entry<Served, Set<String>> e) -> e.getKey().describe())
                            .thenComparing(e -> e.getKey().handler().toString()))
                    .ifPresent(e -> {
                        throw new IllegalStateException("paztport.operations.table-path: the handler "
                                + e.getKey().describe() + " is more than one operation of the entrance " + entrance
                                + ", " + String.join(", ", e.getValue()) + ", so the handler that runs cannot tell "
                                + "which one a request has; map each of them to a handler of its own");
                    });
        }
        for (OperationTable.Operation op : table.operations()) {
            List<String> of = new ArrayList<>();
            handlers.getOrDefault(op.name(), Map.of()).values().forEach(handler -> of.add(handler.toString()));
            Collections.sort(of);
            if (of.isEmpty()) {
                throw new IllegalStateException("paztport.operations.table-path: the operation " + describe(op)
                        + ", is not a handler mapping of this service; no handler maps that method, a pattern that "
                        + "normalises to that template and " + (op.query() == null ? "no params condition"
                                : "the params condition " + condition(op.query())));
            }
            if (of.size() > 1) {
                throw new IllegalStateException("paztport.operations.table-path: the operation " + describe(op)
                        + ", is more than one handler of this service, " + of + "; the entrance " + op.method() + " "
                        + op.template() + " tells them apart by something a caller's table cannot hold, such as "
                        + "headers, a media type or a pattern's regex, so map one handler for each of its query "
                        + "conditions");
            }
        }
        return operations;
    }

    /**
     * Whether a mapping's {@code params} condition is one an operation's query condition can be: none, or one
     * non-negated expression {@code name=value}.
     */
    private static boolean expressible(RequestMappingInfo info) {
        Set<NameValueExpression<String>> params = info.getParamsCondition().getExpressions();
        if (params.size() != 1) {
            return params.isEmpty();
        }
        NameValueExpression<String> only = params.iterator().next();
        return !only.isNegated() && only.getValue() != null;
    }

    /**
     * The query condition of a mapping whose {@code params} condition is {@link #expressible}: its one expression
     * {@code name=value}, or null where it has none. The operation the mapping is on an entrance is the one with
     * this condition there ({@link OperationTable#operationFor(String, String, OperationTable.Condition)}).
     */
    private static OperationTable.Condition conditionOf(RequestMappingInfo info) {
        Set<NameValueExpression<String>> params = info.getParamsCondition().getExpressions();
        if (params.isEmpty()) {
            return null;
        }
        NameValueExpression<String> only = params.iterator().next();
        return new OperationTable.Condition(only.getName(), only.getValue());
    }

    /** The refusal of a mapping on {@code entrance} whose {@code params} condition none of its operations hold. */
    private static String unheldCondition(List<OperationTable.Operation> of, RequestMappingInfo info,
            HandlerMethod handler, String entrance) {
        List<String> conditions = new ArrayList<>();
        for (OperationTable.Operation op : of) {
            conditions.add(op.query() == null ? "none" : condition(op.query()));
        }
        return "paztport.operations.table-path: the handler " + handler + " is mapped on the entrance " + entrance
                + " with the params condition " + info.getParamsCondition() + ", which is none of that entrance's "
                + "query conditions in the table, " + String.join(", ", conditions) + "; give it one of those, or "
                + "map it on an entrance the table does not hold";
    }

    /** {@code name, METHOD /template}, and {@code ?parameter=value} where the operation has a query condition. */
    private static String describe(OperationTable.Operation op) {
        return op.name() + ", " + op.method() + " " + op.template()
                + (op.query() == null ? "" : "?" + condition(op.query()));
    }

    private static String condition(OperationTable.Condition query) {
        return query.parameter() + "=" + query.value();
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

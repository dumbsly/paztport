// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Field;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.RecordComponent;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.WildcardType;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.paztport.core.encoding.Jcs;

/**
 * The SDK's public API names no JSON library: a user brings whichever Jackson their framework uses (Spring Boot 4's
 * web layer is on Jackson 3) and never meets the one the SDK reads with. Every class in an exported package, that
 * is every package but {@code internal}, is loaded from this module's own classes, and each public or protected
 * field, constructor, method parameter and return, thrown type, record component, supertype and type-variable
 * bound is walked down to its generic type arguments.
 */
class PublicApiTest {

    private static final List<String> FORBIDDEN = List.of("com.fasterxml.", "tools.jackson.");

    @Test
    void namesNoJsonLibrary() throws Exception {
        List<Class<?>> classes = moduleClasses(Jcs.class, "org.paztport.core");
        assertTrue(classes.size() > 50, "found the module's classes: " + classes.size());
        Set<String> found = new TreeSet<>();
        for (Class<?> c : classes) {
            if (visible(c)) {
                exposedTypes(c, found);
            }
        }
        assertTrue(found.isEmpty(), "public signatures naming a JSON library:\n  " + String.join("\n  ", found));
    }

    /** The walk reaches a forbidden type wherever it hides: in a type argument, a wildcard's bound or an array. */
    @Test
    void walkSeesTypeArguments() {
        Set<String> found = new TreeSet<>();
        exposedTypes(Exposed.class, found);
        assertEquals(Set.of(
                PublicApiTest.class.getName() + "$Exposed component tree: com.fasterxml.jackson.databind.JsonNode",
                PublicApiTest.class.getName() + "$Exposed.<init> param 0: com.fasterxml.jackson.databind.JsonNode",
                PublicApiTest.class.getName() + "$Exposed.of param 0: com.fasterxml.jackson.databind.node.ArrayNode",
                PublicApiTest.class.getName() + "$Exposed.of returns: com.fasterxml.jackson.databind.node.ObjectNode",
                PublicApiTest.class.getName() + "$Exposed.tree returns: com.fasterxml.jackson.databind.JsonNode"),
                found);
    }

    /** A record whose every exposed signature hides a Jackson type one level down; the private method is not seen. */
    public record Exposed(List<Map<String, JsonNode>> tree) {

        public static Optional<? extends ObjectNode> of(ArrayNode[][] nodes) {
            return Optional.empty();
        }

        private static JsonNode hidden() {
            return null;
        }
    }

    /**
     * Every class under {@code root} in the directory or jar {@code anchor} was loaded from, minus the
     * {@code internal} package and anything synthetic or local.
     */
    static List<Class<?>> moduleClasses(Class<?> anchor, String root) throws IOException, URISyntaxException,
            ClassNotFoundException {
        Path base = Path.of(anchor.getProtectionDomain().getCodeSource().getLocation().toURI());
        Path dir = base.resolve(root.replace('.', '/'));
        List<Class<?>> out = new ArrayList<>();
        try (Stream<Path> files = Files.walk(dir)) {
            for (Path p : files.filter(f -> f.toString().endsWith(".class")).sorted().toList()) {
                String rel = base.relativize(p).toString().replace(p.getFileSystem().getSeparator(), ".");
                String name = rel.substring(0, rel.length() - ".class".length());
                if (name.startsWith(root + ".internal.") || name.endsWith("package-info")) {
                    continue;
                }
                Class<?> c = Class.forName(name, false, anchor.getClassLoader());
                if (!c.isSynthetic() && !c.isAnonymousClass() && !c.isLocalClass()) {
                    out.add(c);
                }
            }
        }
        return out;
    }

    /** Adds to {@code found} each exposed member of {@code c} that names a forbidden type, as {@code where: type}. */
    static void exposedTypes(Class<?> c, Set<String> found) {
        String owner = c.getName();
        check(owner + " extends", c.getGenericSuperclass(), found);
        for (Type t : c.getGenericInterfaces()) {
            check(owner + " implements", t, found);
        }
        for (TypeVariable<?> v : c.getTypeParameters()) {
            check(owner + " <" + v.getName() + ">", v, found);
        }
        if (c.isRecord()) {
            for (RecordComponent rc : c.getRecordComponents()) {
                check(owner + " component " + rc.getName(), rc.getGenericType(), found);
            }
        }
        for (Field f : c.getDeclaredFields()) {
            if (exposed(f) && !f.isSynthetic()) {
                check(owner + "." + f.getName(), f.getGenericType(), found);
            }
        }
        for (Constructor<?> k : c.getDeclaredConstructors()) {
            if (exposed(k) && !k.isSynthetic()) {
                executable(owner + ".<init>", k, found);
            }
        }
        for (Method m : c.getDeclaredMethods()) {
            if (exposed(m) && !m.isSynthetic() && !m.isBridge()) {
                check(owner + "." + m.getName() + " returns", m.getGenericReturnType(), found);
                executable(owner + "." + m.getName(), m, found);
            }
        }
    }

    private static void executable(String where, Executable e, Set<String> found) {
        Type[] params = e.getGenericParameterTypes();
        for (int i = 0; i < params.length; i++) {
            check(where + " param " + i, params[i], found);
        }
        for (Type t : e.getGenericExceptionTypes()) {
            check(where + " throws", t, found);
        }
        for (TypeVariable<?> v : e.getTypeParameters()) {
            check(where + " <" + v.getName() + ">", v, found);
        }
    }

    /** A class a user can name: public (or a protected member class), inside classes a user can name. */
    private static boolean visible(Class<?> c) {
        Class<?> outer = c.getDeclaringClass();
        int mods = c.getModifiers();
        boolean own = Modifier.isPublic(mods) || (outer != null && Modifier.isProtected(mods));
        return own && (outer == null || visible(outer));
    }

    private static boolean exposed(Member m) {
        return Modifier.isPublic(m.getModifiers()) || Modifier.isProtected(m.getModifiers());
    }

    private static void check(String where, Type t, Set<String> found) {
        walk(t, new HashSet<>(), where, found);
    }

    /** Walks a type down to its arguments, bounds and components; {@code seen} stops a recursive bound. */
    private static void walk(Type t, Set<Type> seen, String where, Set<String> found) {
        if (t == null || !seen.add(t)) {
            return;
        }
        switch (t) {
            case Class<?> c -> {
                Class<?> named = c;
                while (named.isArray()) {
                    named = named.getComponentType();
                }
                for (String prefix : FORBIDDEN) {
                    if (named.getName().startsWith(prefix)) {
                        found.add(where + ": " + named.getName());
                    }
                }
            }
            case ParameterizedType p -> {
                walk(p.getRawType(), seen, where, found);
                walk(p.getOwnerType(), seen, where, found);
                for (Type a : p.getActualTypeArguments()) {
                    walk(a, seen, where, found);
                }
            }
            case WildcardType w -> {
                for (Type b : w.getUpperBounds()) {
                    walk(b, seen, where, found);
                }
                for (Type b : w.getLowerBounds()) {
                    walk(b, seen, where, found);
                }
            }
            case GenericArrayType g -> walk(g.getGenericComponentType(), seen, where, found);
            case TypeVariable<?> v -> {
                for (Type b : v.getBounds()) {
                    walk(b, seen, where, found);
                }
            }
            default -> throw new IllegalStateException("unknown kind of type " + t);
        }
    }
}

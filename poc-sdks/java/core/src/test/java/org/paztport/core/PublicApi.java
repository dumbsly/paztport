// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Field;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Parameter;
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
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

/**
 * The walk behind each module's {@code PublicApiTest}: what a user of a module can name, and whether any of it
 * names a JSON library or one of the SDK's own {@code internal} types. Shared with the http module's tests through
 * core's test jar, so both modules are held to one walk.
 *
 * <p>For every class a user can name in a module's exported packages (every package but {@code internal}), it
 * reads the supertype and interfaces, the type parameters and their bounds, the record components, and each public
 * or protected field, constructor and method, the method's return, parameters and thrown types, down through every
 * generic type argument, wildcard bound and array. Members a visible class inherits from a supertype a user cannot
 * name, or from an {@code internal} one, are read as the visible class's own. Annotations on all of these are
 * reported apart, as a type can carry a library's annotation without a user having to name it.
 */
public final class PublicApi {

    /** The packages a public signature must not name: JSON libraries, and the SDK's own {@code internal} packages. */
    public static final List<String> FORBIDDEN = List.of("com.fasterxml.", "tools.jackson.",
            "org.paztport.core.internal.", "org.paztport.http.internal.");

    private PublicApi() {
    }

    /** What a walk found: signatures naming a forbidden type, and forbidden annotations, as {@code where: name}. */
    public record Findings(Set<String> types, Set<String> annotations) {

        public Findings {
            types = new TreeSet<>(types);
            annotations = new TreeSet<>(annotations);
        }
    }

    /** Every visible class under {@code root} in the classes {@code anchor} was loaded from, walked. */
    public static Findings module(Class<?> anchor, String root) throws IOException, URISyntaxException,
            ClassNotFoundException {
        Set<String> types = new TreeSet<>();
        Set<String> annotations = new TreeSet<>();
        for (Class<?> c : moduleClasses(anchor, root)) {
            if (visible(c) && !internal(c)) {
                walk(c, types, annotations);
            }
        }
        return new Findings(types, annotations);
    }

    /** One class walked as if a user could name it, whatever its own visibility: for testing the walk. */
    public static Findings of(Class<?> c) {
        Set<String> types = new TreeSet<>();
        Set<String> annotations = new TreeSet<>();
        walk(c, types, annotations);
        return new Findings(types, annotations);
    }

    /**
     * Every class under {@code root} in the directory {@code anchor} was loaded from, minus {@code package-info}
     * and anything synthetic, anonymous or local.
     */
    public static List<Class<?>> moduleClasses(Class<?> anchor, String root) throws IOException,
            URISyntaxException, ClassNotFoundException {
        Path base = Path.of(anchor.getProtectionDomain().getCodeSource().getLocation().toURI());
        Path dir = base.resolve(root.replace('.', '/'));
        List<Class<?>> out = new ArrayList<>();
        try (Stream<Path> files = Files.walk(dir)) {
            for (Path p : files.filter(f -> f.toString().endsWith(".class")).sorted().toList()) {
                String rel = base.relativize(p).toString().replace(p.getFileSystem().getSeparator(), ".");
                String name = rel.substring(0, rel.length() - ".class".length());
                if (name.endsWith("package-info")) {
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

    /** A class a user can name: public (or a protected member class), inside classes a user can name. */
    public static boolean visible(Class<?> c) {
        Class<?> outer = c.getDeclaringClass();
        int mods = c.getModifiers();
        boolean own = Modifier.isPublic(mods) || (outer != null && Modifier.isProtected(mods));
        return own && (outer == null || visible(outer));
    }

    /** In a package named {@code internal}: public only so the library's packages can share it. */
    public static boolean internal(Class<?> c) {
        return c.getPackageName().endsWith(".internal") || c.getPackageName().contains(".internal.");
    }

    private static void walk(Class<?> c, Set<String> types, Set<String> annotations) {
        String owner = c.getName();
        annotations(owner, c, annotations);
        check(owner + " extends", c.getGenericSuperclass(), types);
        for (Type t : c.getGenericInterfaces()) {
            check(owner + " implements", t, types);
        }
        for (TypeVariable<?> v : c.getTypeParameters()) {
            check(owner + " <" + v.getName() + ">", v, types);
        }
        if (c.isRecord()) {
            for (RecordComponent rc : c.getRecordComponents()) {
                check(owner + " component " + rc.getName(), rc.getGenericType(), types);
                annotations(owner + " component " + rc.getName(), rc, annotations);
            }
        }
        members(owner, c, types, annotations);
        // What a user reaches through c but cannot name where it is declared.
        for (Class<?> s : supertypes(c)) {
            if (!visible(s) || internal(s)) {
                members(owner + " (from " + s.getName() + ")", s, types, annotations);
            }
        }
    }

    /** The public and protected fields, constructors and methods {@code c} declares. */
    private static void members(String owner, Class<?> c, Set<String> types, Set<String> annotations) {
        for (Field f : c.getDeclaredFields()) {
            if (exposed(f) && !f.isSynthetic()) {
                check(owner + "." + f.getName(), f.getGenericType(), types);
                annotations(owner + "." + f.getName(), f, annotations);
            }
        }
        for (Constructor<?> k : c.getDeclaredConstructors()) {
            if (exposed(k) && !k.isSynthetic()) {
                executable(owner + ".<init>", k, types, annotations);
            }
        }
        for (Method m : c.getDeclaredMethods()) {
            if (exposed(m) && !m.isSynthetic() && !m.isBridge()) {
                check(owner + "." + m.getName() + " returns", m.getGenericReturnType(), types);
                executable(owner + "." + m.getName(), m, types, annotations);
            }
        }
    }

    /** Every superclass but {@code Object} and every interface {@code c} inherits, nearest first. */
    private static List<Class<?>> supertypes(Class<?> c) {
        List<Class<?>> out = new ArrayList<>();
        List<Class<?>> todo = new ArrayList<>();
        todo.add(c);
        while (!todo.isEmpty()) {
            Class<?> k = todo.remove(0);
            List<Class<?>> next = new ArrayList<>(List.of(k.getInterfaces()));
            if (k.getSuperclass() != null && k.getSuperclass() != Object.class) {
                next.add(0, k.getSuperclass());
            }
            for (Class<?> s : next) {
                if (!out.contains(s)) {
                    out.add(s);
                    todo.add(s);
                }
            }
        }
        return out;
    }

    private static void executable(String where, Executable e, Set<String> types, Set<String> annotations) {
        annotations(where, e, annotations);
        Type[] params = e.getGenericParameterTypes();
        for (int i = 0; i < params.length; i++) {
            check(where + " param " + i, params[i], types);
        }
        for (Parameter p : e.getParameters()) {
            annotations(where + " param " + p.getName(), p, annotations);
        }
        for (Type t : e.getGenericExceptionTypes()) {
            check(where + " throws", t, types);
        }
        for (TypeVariable<?> v : e.getTypeParameters()) {
            check(where + " <" + v.getName() + ">", v, types);
        }
    }

    private static boolean exposed(Member m) {
        return Modifier.isPublic(m.getModifiers()) || Modifier.isProtected(m.getModifiers());
    }

    private static void annotations(String where, AnnotatedElement e, Set<String> found) {
        for (Annotation a : e.getDeclaredAnnotations()) {
            if (forbidden(a.annotationType())) {
                found.add(where + ": @" + a.annotationType().getName());
            }
        }
    }

    private static void check(String where, Type t, Set<String> found) {
        walkType(t, new HashSet<>(), where, found);
    }

    /** Walks a type down to its arguments, bounds and components; {@code seen} stops a recursive bound. */
    private static void walkType(Type t, Set<Type> seen, String where, Set<String> found) {
        if (t == null || !seen.add(t)) {
            return;
        }
        switch (t) {
            case Class<?> c -> {
                Class<?> named = c;
                while (named.isArray()) {
                    named = named.getComponentType();
                }
                if (forbidden(named)) {
                    found.add(where + ": " + named.getName());
                }
            }
            case ParameterizedType p -> {
                walkType(p.getRawType(), seen, where, found);
                walkType(p.getOwnerType(), seen, where, found);
                for (Type a : p.getActualTypeArguments()) {
                    walkType(a, seen, where, found);
                }
            }
            case WildcardType w -> {
                for (Type b : w.getUpperBounds()) {
                    walkType(b, seen, where, found);
                }
                for (Type b : w.getLowerBounds()) {
                    walkType(b, seen, where, found);
                }
            }
            case GenericArrayType g -> walkType(g.getGenericComponentType(), seen, where, found);
            case TypeVariable<?> v -> {
                for (Type b : v.getBounds()) {
                    walkType(b, seen, where, found);
                }
            }
            default -> throw new IllegalStateException("unknown kind of type " + t);
        }
    }

    private static boolean forbidden(Class<?> c) {
        return FORBIDDEN.stream().anyMatch(prefix -> c.getName().startsWith(prefix));
    }
}

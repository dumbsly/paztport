// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.operation;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.paztport.core.policy.OperationTable;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.Routes;
import org.paztport.core.policy.SignedRoot;
import org.paztport.spring.PaztportAutoConfiguration;
import org.paztport.spring.PaztportProperties;
import org.paztport.spring.internal.OwnMaterial;
import org.paztport.spring.trust.ResponseVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.handler.MappedInterceptor;

/**
 * Reads {@code paztport.operations.*}: this service's own operation table and its receivers' tables, each used only
 * where the signed root covers it. A table is covered when the service's proof bundle holds a proof of its route,
 * {@code <service>/ops:<hash>}, that proves it against one of the pinned roots, the overlap's included.
 *
 * <ul>
 *   <li>The service's own table must be this service's and covered, or the context does not start. Once the handler
 *       mappings are known, each of its operations must be one of them ({@link OperationResolver}). Each request's
 *       handler is checked, as it is about to run, against the operation the request was verified for
 *       ({@link DispatchCheck}), and the answer is attested only once the handler was reached ({@link HandlerReached}).
 *   <li>A receiver's table the bundle holds no proof for is set aside, with one line naming the receiver, and calls
 *       to that receiver name no operation: the receiver then needs a route that names none, so this fails closed.
 *       The receivers' tables are read where the caller is built, so on a service that makes calls
 *       ({@link #receiverTables}).
 *   <li>A table whose proof is there but does not verify against any pinned root stops the start, since the proof
 *       or the root is not the one the policy tool wrote with it.
 * </ul>
 *
 * <p>{@link PaztportAutoConfiguration} imports it; it is not for an application to use directly.
 */
@Configuration(proxyBeanMethods = false)
public class OperationConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(OperationConfiguration.class);

    private static final String OWN = "paztport.operations.table-path";
    private static final String RECEIVERS = "paztport.operations.receiver-tables";

    /**
     * The resolver the inbound filter asks for each request's operation, on a service that names its own: its table,
     * which must be this service's and covered. It checks the table against the handler mappings once they are all
     * known. {@link PaztportProperties} has already refused the property without the proofs and the pinned trust,
     * so both beans are there.
     */
    @Bean
    @ConditionalOnProperty("paztport.operations.table-path")
    OperationResolver paztportOperationResolver(PaztportProperties props, ObjectProvider<ProofBundle> bundle,
            ObjectProvider<ResponseVerifier> trust, ListableBeanFactory beans) {
        ProofBundle proofs = bundle.getObject();
        Path file = Path.of(props.getOperations().getTablePath());
        OperationTable own = OwnMaterial.loadTable(file, OWN);
        if (!own.service().equals(props.getServiceName())) {
            throw new IllegalStateException(OWN + " is the table of " + own.service() + ", not of this service, "
                    + props.getServiceName() + ": " + file);
        }
        if (!present(own, proofs)) {
            throw new IllegalStateException(OWN + " is not covered by the signed root: paztport.proofs-path holds no "
                    + "proof of its route " + Routes.join(own.route()) + "; rebuild the policy with the table beside "
                    + "paths.yaml: " + file);
        }
        requireVerified(own, proofs, trust.getObject().roots(), OWN, file);
        return new OperationResolver(own, beans);
    }

    /**
     * The check, as the first handler a request reaches is about to run, that it is the operation the inbound filter
     * verified the request for ({@link DispatchCheck}), on a service that names its own operations. It is an
     * interceptor so that it sees the handler the DispatcherServlet chose after every filter has run. It is a
     * {@link MappedInterceptor} bean with no path patterns, so every handler mapping in the context picks it up, one
     * the application declares included, and puts it ahead of the interceptors a {@code WebMvcConfigurer} registers:
     * none of those acts on a request it refuses.
     */
    @Bean
    @ConditionalOnProperty("paztport.operations.table-path")
    MappedInterceptor paztportDispatchCheck(OperationResolver operations, PaztportProperties props) {
        return new MappedInterceptor(null, new DispatchCheck(operations, props.getServiceName()));
    }

    /**
     * Paztport's last interceptor ({@link HandlerReached}), which records that the handler was reached, on a service
     * that names its own operations, so that an answer an interceptor writes when it stops the request is not
     * attested. It is registered through {@code addInterceptors} at the lowest precedence, so it runs after the check,
     * which every mapping runs ahead of the registered interceptors, and after every interceptor the application
     * registers with the default order.
     */
    @Bean
    @ConditionalOnProperty("paztport.operations.table-path")
    WebMvcConfigurer paztportHandlerReached() {
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                registry.addInterceptor(new HandlerReached()).order(Ordered.LOWEST_PRECEDENCE);
            }
        };
    }

    /**
     * The receivers' tables this service's calls name operations from: each of
     * {@code paztport.operations.receiver-tables} whose route {@code proofs} holds, in order. One it holds no proof
     * for is set aside, with one line naming its service, so calls to that receiver name no operation.
     *
     * @param proofs this service's bundle, or null where no table is configured
     * @param trust this service's pinned trust, or null where no table is configured
     * @throws IllegalStateException for a table that does not read, or whose proof does not verify against any
     *     pinned root
     */
    public static List<OperationTable> receiverTables(PaztportProperties props, ProofBundle proofs,
            ResponseVerifier trust) {
        List<String> files = props.getOperations().getReceiverTables();
        List<OperationTable> receivers = new ArrayList<>();
        for (int i = 0; i < files.size(); i++) {
            Path file = Path.of(files.get(i));
            String property = RECEIVERS + "[" + i + "]";
            OperationTable table = OwnMaterial.loadTable(file, property);
            if (!present(table, proofs)) {
                LOG.info("{} {} is set aside: paztport.proofs-path holds no proof of the table of {}, so calls to "
                        + "{} name no operation", property, file, table.service(), table.service());
                continue;
            }
            requireVerified(table, proofs, trust.roots(), property, file);
            receivers.add(table);
        }
        return receivers;
    }

    /** Whether {@code proofs} holds a proof of the table's route, whether or not it verifies. */
    private static boolean present(OperationTable table, ProofBundle proofs) {
        return proofs.proofFor(Routes.join(table.route())) != null;
    }

    private static void requireVerified(OperationTable table, ProofBundle proofs, List<SignedRoot> roots,
            String property, Path file) {
        if (!table.coveredBy(proofs, roots)) {
            throw new IllegalStateException(property + ": the proof of its route " + Routes.join(table.route())
                    + " in paztport.proofs-path does not verify against any pinned root; the bundle must be one the "
                    + "policy tool wrote with a pinned root: " + file);
        }
    }
}

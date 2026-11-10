// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.paztport.http.PartnerSessions;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Configuration for the path-attestation glue, bound from {@code paztport.*}. */
@ConfigurationProperties(prefix = "paztport")
public class PaztportProperties implements InitializingBean {

    /** This service's name, used as the stamp svc and the verifier's receiving service. */
    private String serviceName;

    /** This instance's id for stamps; defaults to the container hostname. */
    private String instance;

    /** True only for ingress services allowed to start chains. */
    private boolean origin = false;

    /** True for verifying services; the inbound filter then verifies every request with the Verifier. */
    private boolean verify = false;

    /** Verification mode for verifying services: off, audit, or enforce. */
    private String mode = "enforce";

    /** If set, rejection events are also POSTed to this responder URL. */
    private String responderUrl;

    /** Private key that signs events sent to the responder; required when paztport.responder-url is set. */
    private String eventKeyPath;

    /**
     * How long an event to the responder may take, in milliseconds, from connecting to the end of the answer;
     * positive. It is short because the event is sent on the request thread, before a refusal is answered: a
     * responder that is slow or silent would otherwise hold every refusal for as long as it liked, and this caps
     * that at this long per refusal. It does not stop forged requests sent fast enough from keeping request threads
     * busy, each for up to this long. An event that takes longer is given up and logged.
     */
    private long eventTimeoutMs = 2_000;

    /**
     * How long a call may wait for its answer, in milliseconds; positive. It is the read timeout of the client
     * paztport.tls-bundle makes, and so of every call on the shared RestClient.Builder, and of the egress's calls to
     * the partner: a peer that takes a call and never answers fails it as a timeout rather than holding the calling
     * thread for ever. PooledTlsClient and BoundaryClient say exactly what it bounds on each. Generous, so that a
     * slow but working peer is not cut off.
     */
    private long readTimeoutMs = 30_000;

    /** Shared token for /admin/mode; unset or blank disables the endpoint. */
    private String adminToken;

    /** Path to this service's private key (stamping services only). */
    private String keyPath;

    /** Path to keyring.json (verifying services); it must be signed under the pinned policy key. */
    private String keyringPath;

    /** Path to root.json (verifying services); it must be signed under the pinned policy key. */
    private String rootPath;

    /**
     * Path to policy.pub, the pinned policy public key (verifying services). It is held apart from the keyring
     * because the keyring is only trusted once it verifies under this key.
     */
    private String policyKeyPath;

    /**
     * {@code paztport.overlap.*}: further keyrings and roots the verifier pins beside this service's own, for the
     * rollout of a renewed root or a rotated key. Each must verify under {@code policy-key-path} and be current at
     * startup, or the service does not start. They add only to what the verifier accepts: this service's own
     * {@code keyring-path} and {@code root-path} still serve its partner replies and its egress.
     */
    public static class Overlap {

        /** Paths to further keyring.json files to pin beside paztport.keyring-path, in this order. */
        private List<String> keyringPaths = List.of();

        /** Paths to further root.json files to pin beside paztport.root-path, in this order. */
        private List<String> rootPaths = List.of();

        public List<String> getKeyringPaths() {
            return keyringPaths;
        }

        public void setKeyringPaths(List<String> keyringPaths) {
            this.keyringPaths = keyringPaths;
        }

        public List<String> getRootPaths() {
            return rootPaths;
        }

        public void setRootPaths(List<String> rootPaths) {
            this.rootPaths = rootPaths;
        }
    }

    private final Overlap overlap = new Overlap();

    /** Path to this service's proof bundle (calling services), named for it: proofs-orders.json for orders. */
    private String proofsPath;

    /**
     * {@code paztport.operations.*}: the operation tables, {@code ops-<service>.json}, of a service that names its
     * operations and of the receivers it names them on. A table is used only where the signed root covers it, which
     * this service's proofs ({@code proofs-path}) show against the pinned roots, the overlap's included, so either
     * property needs {@code proofs-path}, {@code keyring-path}, {@code root-path} and {@code policy-key-path}.
     */
    public static class Operations {

        /**
         * Path to this service's own table. It must be covered, or the service does not start, and each of its
         * operations must be a handler mapping: a method, and a pattern that normalises to the operation's template.
         * The inbound filter then confirms the operation each request is dispatched to.
         */
        private String tablePath;

        /**
         * Paths to the tables of the receivers this service calls, at most one per receiver. A call to a receiver
         * with a table names the operation it matches. A table this service's proofs hold no proof for is set
         * aside, with one line naming its service, and calls to that receiver name no operation; one whose proof
         * does not verify stops the start.
         */
        private List<String> receiverTables = List.of();

        public String getTablePath() {
            return tablePath;
        }

        public void setTablePath(String tablePath) {
            this.tablePath = tablePath;
        }

        public List<String> getReceiverTables() {
            return receiverTables;
        }

        public void setReceiverTables(List<String> receiverTables) {
            this.receiverTables = receiverTables;
        }
    }

    private final Operations operations = new Operations();

    /** How old the last stamp may be, in milliseconds. */
    private long maxAgeMs = 5000;

    /**
     * How old the origin's stamp may be, in milliseconds; unset means paztport.max-age-ms, because inside one mesh
     * a request tree is a single call.
     */
    private Long runMaxAgeMs;

    /**
     * Allowed origin service names. Required wherever the trust material (keyring-path, root-path and
     * policy-key-path) is set: a service must say which entry points it accepts. At a partner they check only the
     * responses to its own calls, and paztport.partner.client-origins governs entry.
     */
    private List<String> origins = List.of();

    /**
     * Path prefixes that are neither verified nor attested, each one first path segment: "/" and then letters,
     * digits, ".", "_", "~" or "-", and not "." or "..". An entry that is blank, or has a second "/", a ";", a "%" or
     * a "\", fails start-up, since a trailing comma would otherwise leave an empty entry and so every path
     * unverified. Empty by default, so every path is verified, actuator included; a service whose probes or scrapes
     * reach the application port lists their paths here, or serves them on Boot's management port.
     */
    private List<String> unverifiedPaths = List.of();

    /**
     * The policy names of the services this one calls, by the host it calls them at, where that host is not the
     * name: paztport.receiver-names.orders-internal=orders stamps a call to https://orders-internal/x for orders. A
     * host not listed is its own name, and hosts match with their ASCII letters in lower case, as URI.getHost() gives
     * them, so a key that is not ASCII is refused. An IPv6 host keeps its brackets, so its key is "[[::1]]", since
     * Boot reads a bracketed key as written inside the brackets, and a trailing dot is kept.
     */
    private Map<String, String> receiverNames = new LinkedHashMap<>();

    /**
     * The Spring Boot SSL bundle (spring.ssl.bundle.*) this service presents on its outbound calls and on its
     * events to the responder; unset, they go without a client certificate. Under mutual TLS every receiver requires
     * one, and takes the service it names as the sender. "false" is the same as unset, as Boot reads a property
     * condition, so a test or profile can switch off a bundle an inherited configuration names: there is then no
     * PooledTlsClient, and the service's calls and its events both go without the starter's TLS client. The
     * egress's paztport.boundary.tls-bundle is its own and unaffected.
     */
    private String tlsBundle;

    /** The partner organisation this service calls across the boundary, if it is the egress. */
    private final Boundary boundary = new Boundary();

    /**
     * {@code paztport.boundary.*}: where the partner is, what is pinned for it, and the bundle presented to it. Set
     * {@code url} only on the egress service; it then needs every other field here, and its own stamp key, proofs,
     * keyring, root and policy key.
     */
    public static class Boundary {

        /** The partner's entry service: the boundary stamp's receiver and the "src" of what it answers. */
        private String partner;

        /** The partner's base URL, a scheme and an authority only; setting it makes this service the egress. */
        private String url;

        /**
         * The Spring Boot SSL bundle presented to the partner. It is its own, apart from paztport.tls-bundle, so
         * that the partner's CA is trusted only on calls to the partner, and this organisation's only inside it.
         */
        private String tlsBundle;

        /** Path to the partner's policy public key, pinned out of band; its session replies must be signed by it. */
        private String partnerPolicyKeyPath;

        /**
         * Path to this egress's boundary key: 32 bytes as base64url, which salt the blinded influence it sends. It
         * never leaves this organisation and belongs to this one egress service, shared only by its replicas: the
         * salts do not name the egress, so another service with the same key would derive the same ones.
         */
        private String blindingKeyPath;

        /**
         * How long the session is kept once no call has used it, in milliseconds, before the next call opens a new
         * one. It should be below the partner's own idle period, which forgets the session at its end: a call sent
         * in a session the partner has forgotten is refused, and is not retried.
         */
        private long sessionIdleMs = 600_000;

        public String getPartner() {
            return partner;
        }

        public void setPartner(String partner) {
            this.partner = partner;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public String getTlsBundle() {
            return tlsBundle;
        }

        public void setTlsBundle(String tlsBundle) {
            this.tlsBundle = tlsBundle;
        }

        public String getPartnerPolicyKeyPath() {
            return partnerPolicyKeyPath;
        }

        public void setPartnerPolicyKeyPath(String partnerPolicyKeyPath) {
            this.partnerPolicyKeyPath = partnerPolicyKeyPath;
        }

        public String getBlindingKeyPath() {
            return blindingKeyPath;
        }

        public void setBlindingKeyPath(String blindingKeyPath) {
            this.blindingKeyPath = blindingKeyPath;
        }

        public long getSessionIdleMs() {
            return sessionIdleMs;
        }

        public void setSessionIdleMs(long sessionIdleMs) {
            this.sessionIdleMs = sessionIdleMs;
        }
    }

    /** Set on a partner's entry service, which answers other organisations' session handshakes. */
    private final Partner partner = new Partner();

    /**
     * {@code paztport.partner.*}: what a partner pins for the organisations that call it. Its own keyring, root,
     * policy pin and entry key are the top-level {@code keyring-path}, {@code root-path}, {@code policy-key-path}
     * and {@code key-path}.
     */
    public static class Partner {

        /**
         * Makes this service a partner's entry, which answers POST /paztport/session; it then needs reply-cert-path,
         * client-policy-key-paths and client-origins too.
         */
        private boolean enabled = false;

        /**
         * Path to reply-cert.json: the policy key's certificate for this service's key, the one at
         * paztport.key-path, which signs session replies. Clients accept a reply only until its notAfter, so it is
         * reissued before then.
         */
        private String replyCertPath;

        /** Paths to the policy.pub of each organisation whose sessions may be attested. */
        private List<String> clientPolicyKeyPaths = List.of();

        /** The service names allowed to start a chain in a client's attested session. */
        private List<String> clientOrigins = List.of();

        /** What an unsafe session may not do, as "METHOD /path"; the reply tells the client. */
        private List<String> unsafeDisabled = List.of();

        /** How many sessions one client certificate may hold at once; its least recently used goes first. */
        private int maxSessionsPerPeer = PartnerSessions.DEFAULT_MAX_SESSIONS_PER_PEER;

        /** How long a session no call has used is kept, in milliseconds. */
        private long sessionIdleMs = PartnerSessions.DEFAULT_SESSION_IDLE_MS;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getReplyCertPath() {
            return replyCertPath;
        }

        public void setReplyCertPath(String replyCertPath) {
            this.replyCertPath = replyCertPath;
        }

        public List<String> getClientPolicyKeyPaths() {
            return clientPolicyKeyPaths;
        }

        public void setClientPolicyKeyPaths(List<String> clientPolicyKeyPaths) {
            this.clientPolicyKeyPaths = clientPolicyKeyPaths;
        }

        public List<String> getClientOrigins() {
            return clientOrigins;
        }

        public void setClientOrigins(List<String> clientOrigins) {
            this.clientOrigins = clientOrigins;
        }

        public List<String> getUnsafeDisabled() {
            return unsafeDisabled;
        }

        public void setUnsafeDisabled(List<String> unsafeDisabled) {
            this.unsafeDisabled = unsafeDisabled;
        }

        public int getMaxSessionsPerPeer() {
            return maxSessionsPerPeer;
        }

        public void setMaxSessionsPerPeer(int maxSessionsPerPeer) {
            this.maxSessionsPerPeer = maxSessionsPerPeer;
        }

        public long getSessionIdleMs() {
            return sessionIdleMs;
        }

        public void setSessionIdleMs(long sessionIdleMs) {
            this.sessionIdleMs = sessionIdleMs;
        }
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getInstance() {
        return instance;
    }

    public void setInstance(String instance) {
        this.instance = instance;
    }

    public boolean isOrigin() {
        return origin;
    }

    public void setOrigin(boolean origin) {
        this.origin = origin;
    }

    public boolean isVerify() {
        return verify;
    }

    public void setVerify(boolean verify) {
        this.verify = verify;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public String getResponderUrl() {
        return responderUrl;
    }

    public void setResponderUrl(String responderUrl) {
        this.responderUrl = responderUrl;
    }

    public String getEventKeyPath() {
        return eventKeyPath;
    }

    public void setEventKeyPath(String eventKeyPath) {
        this.eventKeyPath = eventKeyPath;
    }

    public long getEventTimeoutMs() {
        return eventTimeoutMs;
    }

    public void setEventTimeoutMs(long eventTimeoutMs) {
        this.eventTimeoutMs = eventTimeoutMs;
    }

    public long getReadTimeoutMs() {
        return readTimeoutMs;
    }

    public void setReadTimeoutMs(long readTimeoutMs) {
        this.readTimeoutMs = readTimeoutMs;
    }

    public String getAdminToken() {
        return adminToken;
    }

    public void setAdminToken(String adminToken) {
        this.adminToken = adminToken;
    }

    /**
     * Overlap files are pinned by the verifier, which exists only where all three of its own paths are set; asked for
     * without it they would be ignored without a word, on a partner's entry as on any other service, so the context
     * refuses to start instead. An operation table is likewise refused without the proofs and the pinned trust it is
     * checked against. An unverified path that is not one first path segment is refused too, as the filters refuse it
     * themselves.
     */
    @Override
    public void afterPropertiesSet() {
        InboundFilter.requireWellFormed(unverifiedPaths);
        boolean overlapping = !overlap.getKeyringPaths().isEmpty() || !overlap.getRootPaths().isEmpty();
        if (overlapping && (keyringPath == null || rootPath == null || policyKeyPath == null)) {
            throw new IllegalStateException("paztport.overlap.keyring-paths or paztport.overlap.root-paths is set "
                    + "but paztport.keyring-path, paztport.root-path and paztport.policy-key-path are not all set");
        }
        boolean tables = operations.getTablePath() != null || !operations.getReceiverTables().isEmpty();
        if (tables && (proofsPath == null || keyringPath == null || rootPath == null || policyKeyPath == null)) {
            throw new IllegalStateException("paztport.operations.table-path or paztport.operations.receiver-tables "
                    + "is set but paztport.proofs-path, paztport.keyring-path, paztport.root-path and "
                    + "paztport.policy-key-path are not all set: a table is used only where the signed root covers "
                    + "it, which the proofs show against the pinned roots");
        }
    }

    public Overlap getOverlap() {
        return overlap;
    }

    public Operations getOperations() {
        return operations;
    }

    public String getKeyPath() {
        return keyPath;
    }

    public void setKeyPath(String keyPath) {
        this.keyPath = keyPath;
    }

    public String getKeyringPath() {
        return keyringPath;
    }

    public void setKeyringPath(String keyringPath) {
        this.keyringPath = keyringPath;
    }

    public String getRootPath() {
        return rootPath;
    }

    public void setRootPath(String rootPath) {
        this.rootPath = rootPath;
    }

    public String getPolicyKeyPath() {
        return policyKeyPath;
    }

    public void setPolicyKeyPath(String policyKeyPath) {
        this.policyKeyPath = policyKeyPath;
    }

    public String getProofsPath() {
        return proofsPath;
    }

    public void setProofsPath(String proofsPath) {
        this.proofsPath = proofsPath;
    }

    public long getMaxAgeMs() {
        return maxAgeMs;
    }

    public void setMaxAgeMs(long maxAgeMs) {
        this.maxAgeMs = maxAgeMs;
    }

    public Long getRunMaxAgeMs() {
        return runMaxAgeMs;
    }

    public void setRunMaxAgeMs(Long runMaxAgeMs) {
        this.runMaxAgeMs = runMaxAgeMs;
    }

    public List<String> getOrigins() {
        return origins;
    }

    public void setOrigins(List<String> origins) {
        this.origins = origins;
    }

    public List<String> getUnverifiedPaths() {
        return unverifiedPaths;
    }

    public void setUnverifiedPaths(List<String> unverifiedPaths) {
        this.unverifiedPaths = unverifiedPaths;
    }

    public Map<String, String> getReceiverNames() {
        return receiverNames;
    }

    public void setReceiverNames(Map<String, String> receiverNames) {
        this.receiverNames = receiverNames;
    }

    public String getTlsBundle() {
        return tlsBundle;
    }

    public void setTlsBundle(String tlsBundle) {
        this.tlsBundle = tlsBundle;
    }

    public Partner getPartner() {
        return partner;
    }

    public Boundary getBoundary() {
        return boundary;
    }
}

// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Configuration for the path-attestation glue, bound from {@code paztport.*}. */
@ConfigurationProperties(prefix = "paztport")
public class PaztportProperties {

    /** This service's name, used as the stamp svc and the verifier's receiving service. */
    private String serviceName;

    /** This instance's id for stamps; defaults to the container hostname. */
    private String instance;

    /** True only for ingress services allowed to start chains. */
    private boolean origin = false;

    /** True for verifying services; enables the inbound Verifier. */
    private boolean verify = false;

    /** Verification mode for verifying services: off, audit, or enforce. */
    private String mode = "enforce";

    /** If set, rejection events are also POSTed to this responder URL. */
    private String responderUrl;

    /** Private key that signs events sent to the responder; required when {@code responderUrl} is set. */
    private String eventKeyPath;

    /** Shared token for {@code /admin/mode}; unset or blank disables the endpoint. */
    private String adminToken;

    /** Path to this service's private key (stamping services only). */
    private String keyPath;

    /** Path to keyring.json (verifying services). */
    private String keyringPath;

    /** Path to root.json (verifying services). */
    private String rootPath;

    /** Path to this service's proofs-&lt;svc&gt;.json (calling services). */
    private String proofsPath;

    /** Maximum stamp age in milliseconds. */
    private long maxAgeMs = 5000;

    /** Allowed origin service names. */
    private List<String> origins = List.of("gateway");

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

    public String getAdminToken() {
        return adminToken;
    }

    public void setAdminToken(String adminToken) {
        this.adminToken = adminToken;
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

    public List<String> getOrigins() {
        return origins;
    }

    public void setOrigins(List<String> origins) {
        this.origins = origins;
    }
}

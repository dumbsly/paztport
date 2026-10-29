// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The inbound beans other than the filters themselves: the public-writes rule every service has. The filters are
 * registered in {@link PaztportAutoConfiguration}, which imports this; it is not for an application to use
 * directly.
 */
@Configuration(proxyBeanMethods = false)
class InboundConfiguration {

    /** Always present: the rule needs no keys, only this service's name for its trace line. */
    @Bean
    PublicWrites paztportPublicWrites(PaztportProperties props) {
        return new PublicWrites(props.getServiceName());
    }
}

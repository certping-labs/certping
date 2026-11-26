// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement;

import com.certmanagement.support.config.IncidentsProperties;
import com.certmanagement.support.config.IntegrationProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import com.certmanagement.security.JwtProperties;
import com.certmanagement.internal.grpc.InternalGrpcProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties({
        IncidentsProperties.class,
        IntegrationProperties.class,
        JwtProperties.class,
        InternalGrpcProperties.class
})
public class CertManagementServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(CertManagementServiceApplication.class, args);
    }
}

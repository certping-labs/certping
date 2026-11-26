// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import com.certmanagement.constants.Paths;
import com.certmanagement.interceptor.AuditInterceptor;
import com.certmanagement.interceptor.RequestContextInterceptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.orm.jpa.support.OpenEntityManagerInViewInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    /**
     * Requests that call a customer server mid-request, or that must never hold two connections at once.
     * Under open-in-view the first query binds a pool connection to the request's EntityManager, and
     * Hibernate holds it until the request ends, so these run without it and their transactions return
     * the connection when they commit.
     */
    static final String[] OUTSIDE_OPEN_IN_VIEW = {
            // Password sign-in holds one connection at a time and none while BCrypt runs (AdminUserService
            // .authenticate); open-in-view would pin one for the whole request, and a wrong password's count
            // would then need a second.
            Paths.AUTH_LOGIN, Paths.ADMIN_LOGIN, Paths.AUTH_LOGIN_MFA,
            // Audit exports stream for seconds on an async thread: their gate and stream transactions each take
            // and return a connection, and open-in-view must not pin another for the whole download.
            Paths.AUDIT_LOGS_EXPORT, Paths.AUDIT_LOGS_ACCESS_EXPORT, Paths.ADMIN_AUDIT_LOGS_EXPORT};

    @Autowired
    private RequestContextInterceptor requestContextInterceptor;

    @Autowired
    private AuditInterceptor auditInterceptor;

    @Autowired
    private ObjectProvider<OpenEntityManagerInViewInterceptor> openInView;

    /** Replaces Spring Boot's own registration, which backs off when this bean exists and cannot exclude paths. */
    @Bean
    @ConditionalOnProperty(prefix = "spring.jpa", name = "open-in-view", havingValue = "true", matchIfMissing = true)
    public OpenEntityManagerInViewInterceptor openEntityManagerInViewInterceptor() {
        return new OpenEntityManagerInViewInterceptor();
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(requestContextInterceptor)
                .addPathPatterns("/api/**");
        // AuditInterceptor runs after RequestContextInterceptor to have full context
        registry.addInterceptor(auditInterceptor)
                .addPathPatterns("/api/**");
        // Last, as Spring Boot registered it.
        openInView.ifAvailable(interceptor -> registry.addWebRequestInterceptor(interceptor)
                .excludePathPatterns(OUTSIDE_OPEN_IN_VIEW));
    }
}

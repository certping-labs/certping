// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.aws;

import com.certping.agent.deployment.adapter.aws.AwsScopeSupport;
import com.certping.agent.deployment.cloud.aws.AwsAuthMode;
import com.certping.agent.deployment.cloud.aws.AwsAuthSecret;
import com.certping.agent.deployment.cloud.aws.AwsCloudCredentialResolver;
import com.certping.agent.discovery.DiscoveryAdapter;
import com.certping.agent.discovery.DiscoveryAdapterFor;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDiscoveryMessage;
import com.certping.agent.model.message.DiscoveredCertEntry;
import com.certping.agent.secrets.SecretStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.services.acm.AcmClient;
import tools.jackson.databind.ObjectMapper;

import com.certping.agent.discovery.DiscoveryResult;
import com.certping.agent.model.message.DiscoveryFailedScope;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Pattern;

/**
 * Scans AWS for ACM certificates: the agent's own account, or every account of an AWS
 * Organization when it is allowed to list them.
 *
 * <p>The agent first gets hub credentials (its own identity, keys, or a hub role). It lists the
 * organization's active accounts (or uses {@code accountIds}), assumes the read-only member role in
 * each one, finds its enabled regions (or uses {@code regions}), and reads ACM everywhere. One
 * failing account or region never stops the rest of the scan.
 */
@Slf4j
@Component
@DiscoveryAdapterFor(TargetType.AWS_ORGANIZATION)
public class AwsOrganizationDiscoveryAdapter implements DiscoveryAdapter {

    private static final String CTX = "AWS Organization Discovery";
    private static final int MAX_PARALLEL_ACCOUNTS = 4;
    private static final Pattern ACCOUNT_ID = Pattern.compile("\\d{12}");

    private final SecretStore secretStore;
    private final ObjectMapper objectMapper;
    private final AwsCloudCredentialResolver credentialResolver;
    private final AwsAcmDiscoveryAdapter acmDiscovery;
    private final AwsOrganizationClients clients;

    public AwsOrganizationDiscoveryAdapter(SecretStore secretStore, ObjectMapper objectMapper,
            AwsCloudCredentialResolver credentialResolver, AwsAcmDiscoveryAdapter acmDiscovery,
            AwsOrganizationClients clients) {
        this.secretStore = secretStore;
        this.objectMapper = objectMapper;
        this.credentialResolver = credentialResolver;
        this.acmDiscovery = acmDiscovery;
        this.clients = clients;
    }

    @Override
    public List<DiscoveredCertEntry> discover(CertDiscoveryMessage message) {
        return discoverWithFailedScopes(message).certificates();
    }

    /**
     * Scans every account and region. An account or region that fails is reported in
     * {@code failedScopes} (AWS_ACCOUNT or AWS_REGION) and the rest of the scan continues. The scan
     * fails only when no account could be read at all.
     */
    @Override
    public DiscoveryResult discoverWithFailedScopes(CertDiscoveryMessage message) {
        AwsOrganizationScope scope = parseScope(message.getCredentialScopeJson());
        String homeRegion = scope.region() == null || scope.region().isBlank() ? "us-east-1" : scope.region().trim();
        AwsAuthMode authMode = AwsScopeSupport.parseAuthMode(scope.authMode(), CTX);
        AwsCredentialsProvider hub = credentialResolver.resolve(authMode,
                AwsScopeSupport.toAuthScope(homeRegion, scope.roleArn(), scope.externalId()),
                readSecret(message), CTX);

        String hubAccount;
        try {
            hubAccount = clients.callerAccountId(hub, homeRegion);
        } catch (Exception e) {
            throw new PermanentAgentException("DISCOVERY_AWS_ORG_NO_CREDENTIALS",
                    CTX + " could not sign in to AWS. Give the agent an AWS identity or pick another sign-in mode. "
                            + e.getMessage(), e);
        }
        List<String> accounts = accountsToScan(scope, hub, hubAccount);
        log.info("{}: organizationId={}, hubAccount={}, accounts={}",
                CTX, message.getOrganizationId(), hubAccount, accounts.size());

        List<DiscoveredCertEntry> found = Collections.synchronizedList(new ArrayList<>());
        List<DiscoveryFailedScope> failures = Collections.synchronizedList(new ArrayList<>());
        Set<String> unreadableAccounts = ConcurrentHashMap.newKeySet();
        int threads = Math.max(1, Math.min(MAX_PARALLEL_ACCOUNTS, accounts.size()));
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<?>> work = new ArrayList<>();
            for (String account : accounts) {
                work.add(pool.submit(() -> scanAccount(message, scope, homeRegion, hub, hubAccount, account,
                        found, failures, unreadableAccounts)));
            }
            for (Future<?> f : work) {
                f.get();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TransientAgentException("DISCOVERY_AWS_ORG_INTERRUPTED", CTX + " was interrupted", e);
        } catch (Exception e) {
            throw new TransientAgentException("DISCOVERY_AWS_ORG_ERROR", CTX + " failed: " + e.getMessage(), e);
        } finally {
            pool.shutdownNow();
        }

        if (found.isEmpty() && unreadableAccounts.size() >= accounts.size()) {
            DiscoveryFailedScope first = failures.isEmpty() ? null : failures.get(0);
            throw new PermanentAgentException("DISCOVERY_AWS_ORG_ACCESS_DENIED",
                    CTX + " could not read any account. First problem: "
                            + (first == null ? "unknown" : first.getScopeId() + ": " + first.getMessage()));
        }
        log.info("{}: organizationId={} found {} certificates, {} account or region problems",
                CTX, message.getOrganizationId(), found.size(), failures.size());
        List<DiscoveryFailedScope> sorted = new ArrayList<>(failures);
        sorted.sort(Comparator.comparing((DiscoveryFailedScope f) -> f.getScopeType().name())
                .thenComparing(DiscoveryFailedScope::getScopeId));
        return new DiscoveryResult(found, sorted);
    }

    private void scanAccount(CertDiscoveryMessage message, AwsOrganizationScope scope, String homeRegion,
            AwsCredentialsProvider hub, String hubAccount, String account,
            List<DiscoveredCertEntry> found, List<DiscoveryFailedScope> failures, Set<String> unreadableAccounts) {
        AwsOrganizationClients.MemberCredentials member = null;
        try {
            AwsCredentialsProvider creds;
            if (account.equals(hubAccount)) {
                creds = hub;
            } else {
                String roleArn = "arn:" + partition(homeRegion) + ":iam::" + account + ":role/"
                        + scope.memberRoleOrDefault();
                member = clients.assumeMemberRole(hub, roleArn, scope.externalId(), homeRegion);
                creds = member.provider();
            }
            List<String> regions = regionsToScan(scope, creds, homeRegion, account, failures);
            int failedRegions = 0;
            for (String region : regions) {
                String scopeId = account + "/" + region;
                try (AcmClient acm = clients.acmClient(region, creds)) {
                    List<String> unreadable = new ArrayList<>();
                    found.addAll(acmDiscovery.discoverCertificates(acm, message.getOrganizationId(), unreadable));
                    if (!unreadable.isEmpty()) {
                        DiscoveryFailedScope f = AwsAcmDiscoveryAdapter.describeFailure(region, unreadable);
                        failures.add(DiscoveryFailedScope.of(f.getScopeType(), scopeId, f.getErrorCode(),
                                f.getMessage()));
                    }
                } catch (Exception e) {
                    failedRegions++;
                    failures.add(DiscoveryFailedScope.of(DiscoveryFailedScope.ScopeType.AWS_REGION, scopeId,
                            AwsAcmDiscoveryAdapter.errorCodeFor(e, "DISCOVERY_ACM_ACCESS_DENIED", "DISCOVERY_ACM_ERROR"),
                            messageOf(e)));
                    log.warn("{}: account={} region={} skipped: {}", CTX, account, region, e.getMessage());
                }
            }
            if (!regions.isEmpty() && failedRegions == regions.size()) {
                unreadableAccounts.add(account);
            }
        } catch (Exception e) {
            unreadableAccounts.add(account);
            failures.add(DiscoveryFailedScope.of(DiscoveryFailedScope.ScopeType.AWS_ACCOUNT, account,
                    AwsAcmDiscoveryAdapter.errorCodeFor(e, "DISCOVERY_AWS_ACCOUNT_ACCESS_DENIED",
                            "DISCOVERY_AWS_ACCOUNT_ERROR"),
                    messageOf(e)));
            log.warn("{}: account={} skipped: {}", CTX, account, e.getMessage());
        } finally {
            if (member != null) {
                member.close();
            }
        }
    }

    private List<String> accountsToScan(AwsOrganizationScope scope, AwsCredentialsProvider hub,
            String hubAccount) {
        if (scope.accountIds() != null && !scope.accountIds().isEmpty()) {
            List<String> ids = scope.accountIds().stream().map(String::trim).distinct().sorted().toList();
            for (String id : ids) {
                if (!ACCOUNT_ID.matcher(id).matches()) {
                    throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                            CTX + ": accountIds must be 12-digit AWS account IDs");
                }
            }
            return ids;
        }
        try {
            List<String> ids = clients.listActiveAccountIds(hub);
            return ids.isEmpty() ? List.of(hubAccount) : ids;
        } catch (Exception e) {
            // Not in an Organization, or not allowed to list it: scan the agent's own account.
            log.info("{}: could not list organization accounts, scanning account {} only: {}",
                    CTX, hubAccount, e.getMessage());
            return List.of(hubAccount);
        }
    }

    private List<String> regionsToScan(AwsOrganizationScope scope, AwsCredentialsProvider creds,
            String homeRegion, String account, List<DiscoveryFailedScope> failures) {
        if (scope.regions() != null && !scope.regions().isEmpty()) {
            return scope.regions().stream().map(String::trim).distinct().sorted().toList();
        }
        try {
            List<String> regions = clients.enabledRegions(creds);
            return regions.isEmpty() ? List.of(homeRegion) : regions;
        } catch (Exception e) {
            // The other regions of this account were not seen, so the account is incomplete.
            failures.add(DiscoveryFailedScope.of(DiscoveryFailedScope.ScopeType.AWS_ACCOUNT, account,
                    "DISCOVERY_AWS_REGIONS_UNLISTED",
                    "Could not list enabled regions (account:ListRegions); scanned " + homeRegion + " only. "
                            + messageOf(e)));
            log.warn("{}: account={} could not list regions, scanning {} only: {}",
                    CTX, account, homeRegion, e.getMessage());
            return List.of(homeRegion);
        }
    }

    private static String messageOf(Exception e) {
        String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
        return msg.length() > 500 ? msg.substring(0, 500) : msg;
    }

    static String partition(String region) {
        if (region.startsWith("us-gov-")) {
            return "aws-us-gov";
        }
        if (region.startsWith("cn-")) {
            return "aws-cn";
        }
        return "aws";
    }

    private AwsOrganizationScope parseScope(String json) {
        if (json == null || json.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID", CTX + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(json, AwsOrganizationScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private AwsAuthSecret readSecret(CertDiscoveryMessage message) {
        if (message.getDeploymentCredHandle() == null || message.getDeploymentCredHandle().isBlank()) {
            return AwsAuthSecret.empty();
        }
        return AwsScopeSupport.parseKvSecret(objectMapper, secretStore.read(message.getDeploymentCredHandle()), CTX);
    }
}

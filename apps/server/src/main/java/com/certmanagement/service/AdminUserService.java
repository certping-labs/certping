// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.exception.ConflictException;
import com.certmanagement.dto.auth.SetupRequest;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.dto.auth.ChangePasswordRequest;
import com.certmanagement.dto.auth.CreateUserRequest;
import com.certmanagement.dto.auth.LocalLoginRequest;
import com.certmanagement.dto.auth.LocalLoginResponse;

import com.certmanagement.entity.Role;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.constants.JwtClaims;
import com.certmanagement.security.AccessToken;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.PermissionGrantPolicy;
import com.certmanagement.security.SignInAccount;
import com.certmanagement.security.SignInRefusedException;
import com.certmanagement.security.Permissions;
import com.certmanagement.service.audit.AccessAuditRecorder;
import com.certmanagement.service.audit.AuthAuditRecorder;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.certmanagement.utils.RequestContextLogger;
import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.security.SignInFailures;

/**
 * Service for local (username/password) user authentication and management.
 *
 * Additional local users are created via POST /api/v1/admin/users
 * (requires users:create or users:manage), using the organization from the caller's JWT context.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminUserService {

    private final UserRepository userRepository;
    private final OrganizationRepository organizationRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final PermissionGrantPolicy grantPolicy;
    private final AuthAuditRecorder authAuditRecorder;
    private final LoginAttemptService loginAttemptService;
    private final PlatformTransactionManager transactionManager;
    private final AccessAuditRecorder accessAudit;
    private final PasswordPolicy passwordPolicy;

    /**
     * Setter-injected so the many existing constructor-built test doubles keep working: with no
     * {@link MfaService} the sign-in never asks for a second factor.
     */
    private MfaService mfaService;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setMfaService(MfaService mfaService) {
        this.mfaService = mfaService;
    }

    /** Setter-injected for the same reason as {@link #mfaService}; without it only refresh tokens are revoked. */
    private SessionRevocationService sessionRevocationService;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setSessionRevocationService(SessionRevocationService sessionRevocationService) {
        this.sessionRevocationService = sessionRevocationService;
    }

    /** Any constant shared by every pod: the key of the advisory lock first-run setup holds. */
    static final long FIRST_RUN_SETUP_LOCK_KEY = 0x63657274_70696e67L;

    private volatile String dummyPasswordHash;

    private static final AuditReason INVALID_CREDENTIALS = SignInFailures.INVALID_CREDENTIALS;
    private static final AuditReason ACCOUNT_LOCKED = SignInFailures.ACCOUNT_LOCKED;
    private static final AuditReason ACCOUNT_DISABLED = SignInFailures.ACCOUNT_DISABLED;
    private static final AuditReason ORGANIZATION_SUSPENDED = SignInFailures.ORGANIZATION_SUSPENDED;

    @Value("${app.bootstrap-super-admin.username}")
    private String bootstrapSuperAdminUsername;

    @Value("${app.bootstrap-super-admin.email}")
    private String bootstrapSuperAdminEmail;

    @Value("${app.bootstrap-super-admin.password}")
    private String bootstrapSuperAdminPassword;

    @Value("${app.bootstrap-super-admin.display-name}")
    private String bootstrapSuperAdminDisplayName;

    /**
     * Check if the system has been initialized (any users exist).
     */
    public boolean isSystemInitialized() {
        return userRepository.count() > 0;
    }

    /**
     * Create a new local user from a request DTO.
     * Called from AdminController (requires users:create permission).
     */
    @Transactional
    public User createUserFromRequest(CreateUserRequest request, Organization organization) {
        Set<Role> roles = new HashSet<>();
        if (request.getRoleIds() != null && !request.getRoleIds().isEmpty()) {
            List<Role> foundRoles = roleRepository.findAllById(request.getRoleIds());
            if (foundRoles.size() != request.getRoleIds().size()
                    || !foundRoles.stream().allMatch(role -> isAssignableIn(role, organization))) {
                throw new BadRequestException("One or more role IDs are invalid");
            }
            roles.addAll(foundRoles);
        }
        grantPolicy.assertAssignable(grantPolicy.currentCaller(), roles);

        boolean hasSuperAdmin = roles.stream()
                .map(Role::getName)
                .anyMatch(Permissions.ROLE_SUPER_ADMIN::equals);
        if (hasSuperAdmin && organization != null) {
            throw new BadRequestException("SUPER_ADMIN users cannot be scoped to an organization");
        }

        String resolvedUsername = resolveUsername(request.getUsername(), request.getEmail());
        return createUser(resolvedUsername, request.getPassword(), request.getEmail(), request.getDisplayName(), organization, roles);
    }

    /**
     * True when the request assigns the platform SUPER_ADMIN role. Such users are platform-level
     * and must NOT be scoped to an organization, so callers can relax the org requirement for them.
     */
    public boolean targetsSuperAdminRole(CreateUserRequest request) {
        if (request.getRoleIds() == null || request.getRoleIds().isEmpty()) {
            return false;
        }
        return roleRepository.findAllById(request.getRoleIds()).stream()
                .map(Role::getName)
                .anyMatch(Permissions.ROLE_SUPER_ADMIN::equals);
    }

    /**
     * Whether the first Platform Super Admin still has to be created: true while no user exists at
     * all. Deleted users count, so a wiped-but-not-empty database never reopens setup.
     */
    @Transactional(readOnly = true)
    public boolean isSetupRequired() {
        return userRepository.count() == 0;
    }

    /**
     * Creates the first Platform Super Admin from the first-run setup screen. Refused once any user
     * exists, so the endpoint cannot be used to add a second super admin later. The password must
     * pass the same policy as every other local password, and the account is active at once.
     */
    public User createFirstSuperAdmin(SetupRequest request) {
        TransactionTemplate tx = new TransactionTemplate(transactionManager);
        return tx.execute(status -> {
            // Two setup requests at once would both see no user and create two super admins: the
            // transaction-scoped lock makes the second wait, then see the first one's committed row.
            userRepository.lockForFirstRunSetup(FIRST_RUN_SETUP_LOCK_KEY);
            if (!isSetupRequired()) {
                throw new ConflictException("Setup has already been completed");
            }
            passwordPolicy.validate(request.getPassword(), request.getUsername(), request.getEmail());
            Role superAdminRole = roleRepository.findByNameAndOrganizationIsNull(Permissions.ROLE_SUPER_ADMIN)
                    .orElseThrow(() -> new IllegalStateException(
                            Permissions.ROLE_SUPER_ADMIN + " role not found. Ensure seed data is loaded."));
            Set<Role> roles = new HashSet<>();
            roles.add(superAdminRole);
            String displayName = StringUtils.hasText(request.getDisplayName())
                    ? request.getDisplayName().trim() : request.getUsername().trim();
            User superAdmin = User.builder()
                    .email(request.getEmail().trim().toLowerCase(Locale.ROOT))
                    .username(request.getUsername().trim())
                    .passwordHash(passwordEncoder.encode(request.getPassword()))
                    .displayName(displayName)
                    .organization(null)
                    .authMethod(User.AuthMethod.LOCAL)
                    .active(true)
                    .mustChangePassword(false)
                    .roles(roles)
                    .build();
            User saved = userRepository.save(superAdmin);
            accessAudit.bootstrapSuperAdminCreated(saved, roles);
            contextLogger().warn("First Platform Super Admin '{}' created through first-run setup",
                    saved.getUsername());
            return saved;
        });
    }

    /**
     * Optional non-interactive bootstrap for automation: creates the super admin named by the
     * {@code app.bootstrap-super-admin.*} properties when all of them are set. Nothing is configured
     * by default, so a normal installation creates its first admin through first-run setup
     * instead ({@link #createFirstSuperAdmin}); there is no built-in account or password.
     */
    @Transactional
    public void ensureBootstrapSuperAdmin() {
        if (!StringUtils.hasText(bootstrapSuperAdminUsername)
                || !StringUtils.hasText(bootstrapSuperAdminEmail)
                || !StringUtils.hasText(bootstrapSuperAdminPassword)) {
            if (isSetupRequired()) {
                contextLogger().info("No user exists yet: open the web app to create the first Platform Super Admin "
                        + "(or set BOOTSTRAP_SUPER_ADMIN_USERNAME, _EMAIL and _PASSWORD for an unattended install)");
            }
            return;
        }
        String displayName = StringUtils.hasText(bootstrapSuperAdminDisplayName)
                ? bootstrapSuperAdminDisplayName.trim()
                : bootstrapSuperAdminUsername.trim();

        if (userRepository.findByUsername(bootstrapSuperAdminUsername.trim()).isPresent()
                || userRepository.findByEmail(bootstrapSuperAdminEmail.trim()).isPresent()) {
            contextLogger().debug("Bootstrap SUPER_ADMIN already present");
            return;
        }

        Role superAdminRole = roleRepository.findByNameAndOrganizationIsNull(Permissions.ROLE_SUPER_ADMIN)
                .orElseThrow(() -> new RuntimeException(
                        Permissions.ROLE_SUPER_ADMIN + " role not found. Ensure seed data is loaded."));

        Set<Role> roles = new HashSet<>();
        roles.add(superAdminRole);

        User superAdmin = User.builder()
                .email(bootstrapSuperAdminEmail.trim())
                .username(bootstrapSuperAdminUsername.trim())
                .passwordHash(passwordEncoder.encode(bootstrapSuperAdminPassword))
                .displayName(displayName)
                .organization(null)
                .authMethod(User.AuthMethod.LOCAL)
                .active(true)
                .mustChangePassword(true)
                .roles(roles)
                .build();

        User saved = userRepository.save(superAdmin);
        // Boot has no request or caller, so the row names the system as actor. It joins this
        // transaction: the account and its record commit or roll back together.
        accessAudit.bootstrapSuperAdminCreated(saved, roles);
        contextLogger().warn("Bootstrap SUPER_ADMIN '{}' created with mandatory password change",
                bootstrapSuperAdminUsername.trim());
    }

    /**
     * Authenticate user with username and password.
     *
     * <p>A refusal is a {@link SignInRefusedException} with the same message as before, and is on the audit
     * trail ({@code auth.sign_in_failed}): in the account's trail when the username resolved to one, else as
     * an internal anonymous row that does not store the username. A success is {@code auth.signed_in},
     * queued once the sign-in's transaction commits.
     *
     * <p>Holds at most one pool connection at a time, and none while the password is checked: a short
     * read loads the account, BCrypt runs outside any transaction, then either the failure is counted in
     * a transaction of its own ({@link LoginAttemptService}) or the sign-in completes in one. A flood of
     * wrong passwords therefore cannot exhaust the pool waiting on a second connection. The endpoints that
     * reach here run outside open-in-view ({@code WebConfig.OUTSIDE_OPEN_IN_VIEW}) so nothing else holds one.
     */
    public LocalLoginResponse authenticate(LocalLoginRequest request) {
        try {
            return authenticateOrRefuse(request);
        } catch (SignInRefusedException refused) {
            authAuditRecorder.signInFailed(refused.account(), null, AuthAuditRecorder.Method.PASSWORD, null,
                    refused.reason());
            throw refused;
        }
    }

    private LocalLoginResponse authenticateOrRefuse(LocalLoginRequest request) {
        SignInCandidate candidate = readOnlyTransaction().execute(status -> loadCandidate(request.getUsername()));

        if (candidate == null) {
            contextLogger().warn("Login failed: user not found");
            spendPasswordCheck(request.getPassword());
            throw new SignInRefusedException(INVALID_CREDENTIALS, null, "Invalid username or password");
        }
        if (candidate.refusal() != null) {
            if (candidate.passwordHash() == null) {
                // As long as a wrong password takes, so the answer's timing does not tell the two apart.
                spendPasswordCheck(request.getPassword());
                throw candidate.refusal();
            }
            // Locked, disabled or suspended: only a caller who knows the password learns which. Anyone else
            // gets the answer a wrong password gets, so the refusal tells nothing about the account. The
            // audit row still carries the real reason.
            if (!passwordEncoder.matches(request.getPassword(), candidate.passwordHash())) {
                contextLogger().warn("Login failed: invalid credentials on a refused account");
                throw new SignInRefusedException(candidate.refusal().reason(), candidate.account(),
                        "Invalid username or password");
            }
            throw candidate.refusal();
        }

        if (!passwordEncoder.matches(request.getPassword(), candidate.passwordHash())) {
            recordFailedLogin(candidate.account());
            contextLogger().warn("Login failed: invalid credentials");
            throw new SignInRefusedException(INVALID_CREDENTIALS, candidate.account(), "Invalid username or password");
        }

        if (mfaService != null && mfaService.isEnabled(candidate.account().userId())) {
            // The password was right; the sign-in finishes in authenticateWithMfa. No tokens yet, no
            // auth.signed_in row yet, and the challenge names only the user id.
            contextLogger().info("Password accepted; second factor required");
            return LocalLoginResponse.builder()
                    .mfaRequired(true)
                    .mfaToken(mfaService.challenge(candidate.account().userId()))
                    .build();
        }

        return writeTransaction().execute(status -> completeSignIn(candidate.account()));
    }

    /**
     * Second step of a sign-in whose password was accepted: the challenge {@link #authenticate} returned
     * and a one-time or recovery code. The account's state is checked again (a lock or disable since the
     * first step still refuses), and a wrong code counts toward the lockout like a wrong password.
     */
    public LocalLoginResponse authenticateWithMfa(String mfaToken, String code) {
        try {
            return authenticateWithMfaOrRefuse(mfaToken, code);
        } catch (SignInRefusedException refused) {
            authAuditRecorder.signInFailed(refused.account(), null, AuthAuditRecorder.Method.PASSWORD, null,
                    refused.reason());
            throw refused;
        }
    }

    private LocalLoginResponse authenticateWithMfaOrRefuse(String mfaToken, String code) {
        if (mfaService == null) {
            throw new SignInRefusedException(SignInFailures.MFA_CODE_INVALID, null, "Two-factor sign-in is not available");
        }
        Integer userId = mfaService.verifyChallenge(mfaToken).orElseThrow(() -> new SignInRefusedException(
                SignInFailures.MFA_CODE_INVALID, null, "The sign-in challenge has expired. Sign in again."));
        SignInCandidate candidate = readOnlyTransaction().execute(status -> userRepository.findById(userId)
                .map(user -> loadCandidate(user.getUsername())).orElse(null));
        if (candidate == null) {
            throw new SignInRefusedException(INVALID_CREDENTIALS, null, "Invalid username or password");
        }
        if (candidate.refusal() != null) {
            throw candidate.refusal();
        }
        if (!mfaService.verifyCode(userId, code)) {
            recordFailedLogin(candidate.account());
            contextLogger().warn("Login failed: invalid one-time code");
            throw new SignInRefusedException(SignInFailures.MFA_CODE_INVALID, candidate.account(),
                    "The code was not valid. Try again.");
        }
        return writeTransaction().execute(status -> completeSignIn(candidate.account()));
    }

    /**
     * What the sign-in needs from the account, read in a short read-only transaction: the refusal its state
     * calls for, in the order the checks have always run, or the hash to check the password against.
     */
    private SignInCandidate loadCandidate(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            return null;
        }
        User user = userOpt.get();
        SignInAccount account = SignInAccount.of(user);

        if (user.getPasswordHash() == null) {
            contextLogger().warn("Login failed: no password set for user");
            return new SignInCandidate(account, null,
                    new SignInRefusedException(INVALID_CREDENTIALS, account, noPasswordMessage(user)));
        }
        if (user.isLocked()) {
            contextLogger().warn("Login failed: account locked");
            return new SignInCandidate(account, user.getPasswordHash(),
                    new SignInRefusedException(ACCOUNT_LOCKED, account, "Account is locked. Try again later."));
        }
        if (!Boolean.TRUE.equals(user.getActive())) {
            contextLogger().warn("Login failed: account disabled");
            return new SignInCandidate(account, user.getPasswordHash(),
                    new SignInRefusedException(ACCOUNT_DISABLED, account, "Account is disabled"));
        }
        Organization loginOrg = user.getOrganization();
        if (loginOrg != null
                && (!Boolean.TRUE.equals(loginOrg.getActive()) || Boolean.TRUE.equals(loginOrg.getIsDeleted()))) {
            contextLogger().warn("Login failed: organization suspended or deleted");
            return new SignInCandidate(account, user.getPasswordHash(), new SignInRefusedException(
                    ORGANIZATION_SUSPENDED, account, "Organization is suspended or inactive"));
        }
        return new SignInCandidate(account, user.getPasswordHash(), null);
    }

    /**
     * The password was right: clears the failed-login count and stamps the sign-in (one statement, so a
     * stale entity cannot undo it), issues and records the tokens, and queues {@code auth.signed_in} for
     * the commit. A lock that started while the password was being checked does not stop a sign-in that
     * gave the right password; it never did.
     */
    private LocalLoginResponse completeSignIn(SignInAccount account) {
        User user = userRepository.findById(account.userId()).orElseThrow(() ->
                new SignInRefusedException(INVALID_CREDENTIALS, account, "Invalid username or password"));
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        userRepository.recordSuccessfulLogin(user.getId(), now);

        Organization organization = user.getOrganization();
        String accessToken = jwtTokenProvider.generateAccessToken(user, organization, JwtClaims.AUTH_METHOD_LOCAL);
        String refreshToken = jwtTokenProvider.generateRefreshToken(user, organization);
        // Record issuance so the refresh token can be revoked on logout / rotation.
        // Local username/password login → session-origin LOCAL.
        refreshTokenService.recordIssued(refreshToken, user, JwtClaims.AUTH_METHOD_LOCAL);
        authAuditRecorder.signedIn(account, AuthAuditRecorder.Method.PASSWORD, null);

        contextLogger().info("Local user authenticated successfully");

        return LocalLoginResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .tokenType(JwtClaims.BEARER_TYPE)
                .expiresIn(jwtTokenProvider.getExpirationTime())
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .organizationId(organization != null ? organization.getId() : null)
                .organizationName(organization != null ? organization.getName() : null)
                .roles(user.getRoleNames())
                .permissions(user.getEffectivePermissionNames())
                .mustChangePassword(user.getMustChangePassword())
                .lastLoginAt(now)
                .build();
    }

    /**
     * Runs a password check against a hash no password matches, for a refusal that would otherwise answer
     * faster than a wrong password does (no such account, no password set) and so tell them apart.
     */
    public void spendPasswordCheck(String rawPassword) {
        passwordEncoder.matches(rawPassword == null ? "" : rawPassword, dummyPasswordHash());
    }

    /** Made once, by the configured encoder, so it costs what a real hash costs to check. */
    @PostConstruct
    void initDummyPasswordHash() {
        dummyPasswordHash();
    }

    private String dummyPasswordHash() {
        String hash = dummyPasswordHash;
        if (hash == null) {
            hash = passwordEncoder.encode(UUID.randomUUID().toString());
            dummyPasswordHash = hash;
        }
        return hash;
    }

    /**
     * Counts the failure in its own transaction, the only connection this sign-in then holds, and makes a
     * lock that this failure started visible ({@link AuthAuditRecorder#accountLocked}). A count that cannot
     * be written still ends in the same 401 as any wrong password: a 500 here would tell a caller the
     * password was wrong.
     */
    private void recordFailedLogin(SignInAccount account) {
        try {
            loginAttemptService.recordFailure(account.userId())
                    .filter(LoginAttemptService.FailedLogin::lockStarted)
                    .ifPresent(failed -> authAuditRecorder.accountLocked(account, failed.attempts()));
        } catch (RuntimeException e) {
            contextLogger().error("Failed to record failed login attempt: {}", e.getClass().getSimpleName());
        }
    }

    private TransactionTemplate readOnlyTransaction() {
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        template.setReadOnly(true);
        return template;
    }

    private TransactionTemplate writeTransaction() {
        return new TransactionTemplate(transactionManager);
    }

    /** The account a sign-in resolved to, and either the hash to check or the refusal its state calls for. */
    private record SignInCandidate(SignInAccount account, String passwordHash, SignInRefusedException refusal) {
    }

    /**
     * Change a user's local auth password. The change is {@code auth.password_changed} in this transaction;
     * a wrong current password is that event refused ({@code INVALID_CREDENTIALS}), queued so it survives
     * the rollback and throttled per user.
     */
    @Transactional
    public void changePassword(Integer userId, ChangePasswordRequest request) {
        changePassword(userId, request, null);
    }

    /**
     * As {@link #changePassword(Integer, ChangePasswordRequest)}. A wrong current password counts toward
     * the lockout like a wrong sign-in (in its own transaction, so it survives this one's rollback), and a
     * locked account cannot change its password. On success every other session ends: refresh tokens are
     * revoked and access tokens issued before now are refused, except {@code currentToken}, the one this
     * request came with, so the session that made the change continues.
     */
    @Transactional
    public void changePassword(Integer userId, ChangePasswordRequest request, AccessToken currentToken) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BadRequestException("User not found"));

        if (user.getPasswordHash() == null) {
            throw new BadRequestException("This account has no password set. Ask your admin to set one.");
        }

        if (user.isLocked()) {
            throw new BadRequestException("Account is locked. Try again later.");
        }

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            authAuditRecorder.passwordChangeRefused(SignInAccount.of(user));
            recordFailedLogin(SignInAccount.of(user));
            throw new BadRequestException("Current password is incorrect");
        }

        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new BadRequestException("New passwords do not match");
        }

        passwordPolicy.validate(request.getNewPassword(), user.getUsername(), user.getEmail());

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setMustChangePassword(false);
        user.setUpdatedAt(OffsetDateTime.now(ZoneOffset.UTC));
        userRepository.save(user);
        authAuditRecorder.passwordChanged(SignInAccount.of(user));
        endAllSessions(user.getId(), currentToken);

        contextLogger().info("Password changed successfully");
    }

    private void endAllSessions(Integer userId, AccessToken keep) {
        if (sessionRevocationService != null) {
            sessionRevocationService.endAllSessions(userId, keep);
        } else {
            refreshTokenService.revokeAllForUser(userId);
        }
    }



    /**
     * Create a new user with username/password credentials.
     */
    @Transactional
    public User createUser(String username, String password, String email, String displayName,
                           Organization organization, Set<Role> roles) {
        String resolvedUsername = resolveUsername(username, email);

        // Fast pre-check for the global email uniqueness constraint so the API returns a clean
        // 409 (via DuplicateResourceException) instead of letting the DB throw a 500-shaped
        // DataIntegrityViolationException at flush time. We still rely on the unique index
        // (uk_users_email_global) as the source of truth — see GlobalExceptionHandler for the
        // race-condition safety net.
        if (StringUtils.hasText(email) && userRepository.findByEmail(email.trim()).isPresent()) {
            throw new com.certmanagement.exception.DuplicateResourceException(
                    "A user with this email already exists.");
        }

        String resolvedDisplayName = StringUtils.hasText(displayName) ? displayName.trim() : resolvedUsername;

        User user = User.builder()
                .username(resolvedUsername)
                .passwordHash(passwordEncoder.encode(password))
                .email(email)
                .displayName(resolvedDisplayName)
                .organization(organization)
                .authMethod(User.AuthMethod.LOCAL)
                .active(true)
                .mustChangePassword(true)
                .roles(roles)
                .build();

        User created = userRepository.save(user);
        accessAudit.memberCreated(created, roles, null, User.AuthMethod.LOCAL.name(), null,
                AccessAuditRecorder.Actor.REQUEST);
        // PII: don't log the email or display name — userId is enough for correlation.
        contextLogger().info("Created user id={} with {} role(s) (no individual permission grants)",
                created.getId(), roles.size());
        return created;
    }

    private String resolveUsername(String username, String email) {
        if (StringUtils.hasText(username)) {
            String normalized = username.trim();
            if (userRepository.existsByUsername(normalized)) {
                throw new BadRequestException("Username already exists: " + normalized);
            }
            return normalized;
        }
        return generateUniqueUsernameFromEmail(email);
    }

    private String generateUniqueUsernameFromEmail(String email) {
        String emailValue = email == null ? "" : email.trim();
        int atIndex = emailValue.indexOf('@');
        String localPart = atIndex > 0 ? emailValue.substring(0, atIndex) : emailValue;

        String base = localPart.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9._-]", "-")
                .replaceAll("[-.]{2,}", "-")
                .replaceAll("^-+|-+$", "");

        if (!StringUtils.hasText(base)) {
            base = "user";
        }
        if (base.length() > 50) {
            base = base.substring(0, 50);
        }

        String candidate = base;
        int suffix = 1;
        while (userRepository.existsByUsername(candidate)) {
            String suffixText = "-" + suffix;
            int maxBaseLength = 50 - suffixText.length();
            String shortenedBase = base.length() > maxBaseLength ? base.substring(0, maxBaseLength) : base;
            candidate = shortenedBase + suffixText;
            suffix++;
        }
        return candidate;
    }

    /** System roles fit any organization; a custom role only the organization that owns it. */
    private static boolean isAssignableIn(Role role, Organization organization) {
        if (role.getOrganization() == null) {
            return true;
        }
        return organization != null && organization.getId().equals(role.getOrganization().getId());
    }

    private Logger contextLogger() {
        return RequestContextLogger.getLogger(AdminUserService.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }

    private String noPasswordMessage(User user) {
        if (user.getAuthMethod() == User.AuthMethod.SSO) {
            return "Your account is not associated with a password. "
                    + "Sign in using the SSO link for your organization.";
        }
        return "Your account is not associated with a password. "
                + "Use \"Forgot password\" to set one.";
    }
}

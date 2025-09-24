package io.github.asharapov.nexus.casc.internal.handlers;

import io.github.asharapov.nexus.casc.internal.Utils;
import io.github.asharapov.nexus.casc.internal.model.SecurityConfig;
import org.apache.shiro.util.ThreadContext;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.ldap.persist.LdapConfigurationManager;
import org.sonatype.nexus.ldap.persist.LdapServerNotFoundException;
import org.sonatype.nexus.ldap.persist.entity.Connection;
import org.sonatype.nexus.ldap.persist.entity.LdapConfiguration;
import org.sonatype.nexus.ldap.persist.entity.Mapping;
import org.sonatype.nexus.security.SecurityApi;
import org.sonatype.nexus.security.SecuritySystem;
import org.sonatype.nexus.security.anonymous.AnonymousManager;
import org.sonatype.nexus.security.authz.AuthorizationManager;
import org.sonatype.nexus.security.authz.NoSuchAuthorizationManagerException;
import org.sonatype.nexus.security.privilege.NoSuchPrivilegeException;
import org.sonatype.nexus.security.privilege.Privilege;
import org.sonatype.nexus.security.realm.RealmManager;
import org.sonatype.nexus.security.realm.SecurityRealm;
import org.sonatype.nexus.security.realm.RealmConfiguration;
import org.sonatype.nexus.security.role.NoSuchRoleException;
import org.sonatype.nexus.security.role.Role;
import org.sonatype.nexus.security.role.RoleIdentifier;
import org.sonatype.nexus.security.subject.FakeAlmightySubject;
import org.sonatype.nexus.security.user.NoSuchUserManagerException;
import org.sonatype.nexus.security.user.User;
import org.sonatype.nexus.security.user.UserManager;
import org.sonatype.nexus.security.user.UserNotFoundException;
import org.sonatype.nexus.security.user.UserSearchCriteria;
import org.sonatype.nexus.security.user.UserStatus;
import org.sonatype.nexus.ssl.CertificateUtil;
import org.sonatype.nexus.ssl.KeyNotFoundException;
import org.sonatype.nexus.ssl.KeystoreException;
import org.sonatype.nexus.ssl.TrustStore;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author Anton Sharapov
 */
@Named
@Singleton
public class SecurityConfigHandler {

    private static final TrustManager ACCEPT_ALL_TRUST_MANAGER = new X509TrustManager() {
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        @Override
        public void checkClientTrusted(final X509Certificate[] certs, final String authType) {
            // all trusted
        }

        @Override
        public void checkServerTrusted(final X509Certificate[] certs, final String authType) {
            // all trusted
        }
    };

    private static final Logger log = LoggerFactory.getLogger(SecurityConfigHandler.class);
    private static final String DEFAULT_AUTH_SOURCE = "default";

    private final AnonymousManager anonymousManager;
    private final RealmManager realmManager;
    private final RealmConfiguration realmConfiguration;
    private final SecurityApi securityApi;
    private final SecuritySystem securitySystem;
    private final LdapConfigurationManager ldapConfigurationManager;
    private final TrustStore trustStore;

    @Inject
    SecurityConfigHandler(
            final AnonymousManager anonymousManager,
            final RealmManager realmManager,
            final RealmConfiguration realmConfiguration,
            final SecurityApi securityApi,
            final SecuritySystem securitySystem,
            final LdapConfigurationManager ldapConfigurationManager,
            final TrustStore trustStore) {
        this.anonymousManager = anonymousManager;
        this.realmManager = realmManager;
        this.realmConfiguration = realmConfiguration;
        this.securityApi = securityApi;
        this.securitySystem = securitySystem;
        this.ldapConfigurationManager = ldapConfigurationManager;
        this.trustStore = trustStore;
    }

    public SecurityConfig load(final Options opts) {
        final SecurityConfig config = new SecurityConfig();
        config.anonymousAccess = getAnonymousAccess();
        config.trustedCerts = getTrustedCertificates();
        config.ldapServers = getLdapConfigurations();
        config.realms = getRealms();
        config.privileges = getPrivileges(opts);
        config.privilegesToDelete = new ArrayList<>();
        config.roles = getRoles(opts);
        config.rolesToDelete = new ArrayList<>();
        config.users = getUsers(opts);
        config.usersToDelete = new ArrayList<>();
        config.pruneOtherUsers = false;
        return config;
    }

    public void store(final SecurityConfig config) {
        if (config == null) {
            return;
        }
        setAnonymousAccess(config.anonymousAccess);
        uploadTrustedCertificates(config.trustedCerts);
        updateLdapConfigurations(config.ldapServers);
        updateRealms(config.realms);
        updatePrivileges(config.privileges);
        deletePrivileges(config.privilegesToDelete);
        updateRoles(config.roles);
        deleteRoles(config.rolesToDelete);
        updateUsers(config.users);
        deleteUsers(config.usersToDelete);
        pruneOtherUsers(config.pruneOtherUsers, config.users);
    }


    private Boolean getAnonymousAccess() {
        return anonymousManager.getConfiguration().isEnabled();
    }

    private void setAnonymousAccess(final Boolean enabled) {
        if (enabled == null) {
            return;
        }
        securityApi.setAnonymousAccess(enabled);
    }

    private SecurityConfig.TrustedStore getTrustedCertificates() {
        final SecurityConfig.TrustedStore result = new SecurityConfig.TrustedStore();
        result.fromPEMFiles = new ArrayList<>();
        result.fromServers = new ArrayList<>();
        return result;
    }

    private void uploadTrustedCertificates(final SecurityConfig.TrustedStore trustedCerts) {
        if (trustedCerts == null) {
            return;
        }
        if (trustedCerts.fromPEMFiles != null) {
            trustedCerts.fromPEMFiles.stream()
                    .flatMap(uri -> Utils.extendDirReferences(uri, ".pem"))
                    .flatMap(this::retrieveCertificates)
                    .forEach(this::importCertificate);
        }
        if (trustedCerts.fromServers != null) {
            trustedCerts.fromServers.stream()
                    .flatMap(this::retrieveCertificates)
                    .forEach(this::importCertificate);
        }
    }

    private Stream<Certificate> retrieveCertificates(final URI uri) {
        if (uri == null)
            return Stream.empty();
        log.info("Reading content from '{}' ...", uri);

        final String pemText;
        try {
            pemText = new String(Utils.load(uri), StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.warn("Can't load content from uri '" + uri + "' : " + e.getMessage(), e);
            return Stream.empty();
        }

        try {
            try (PEMParser pemReader = new PEMParser(new StringReader(pemText))) {
                final ArrayList<Certificate> list = new ArrayList<>();
                final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
                Object object;
                while ((object = pemReader.readObject()) != null) {
                    if (object instanceof X509CertificateHolder) {
                        final X509CertificateHolder holder = (X509CertificateHolder) object;
                        final Certificate cert = converter.getCertificate(holder);
                        list.add(cert);
                    }
                }
                return list.stream();
            }
        } catch (CertificateException | IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    private Stream<Certificate> retrieveCertificates(final SecurityConfig.HostCertificate model) {
        if (model == null || model.host == null || model.host.isEmpty()) {
            return Stream.empty();
        }
        log.info("Retrieving certificate from {}:{} using direct socket connection", model.host, model.port);

        try {
            SSLSocket socket = null;
            try {
                SSLContext sc = SSLContext.getInstance("TLS");
                sc.init(trustStore.getKeyManagers(), new TrustManager[]{ACCEPT_ALL_TRUST_MANAGER}, null);

                javax.net.ssl.SSLSocketFactory sslSocketFactory = sc.getSocketFactory();
                socket = (SSLSocket) sslSocketFactory.createSocket(model.host, model.port);
                socket.startHandshake();

                SSLSession session = socket.getSession();
                return Arrays.stream(session.getPeerCertificates());
            } finally {
                if (socket != null) {
                    socket.close();
                }
            }
        } catch (Exception e) {
            log.warn("Can't retrieve certificates from server " + model.host + ":" + model.port + " : " + e.getMessage(), e);
            return Stream.empty();
        }
    }

    private void importCertificate(final Certificate cert) {
        final String fingerprint;
        try {
            fingerprint = CertificateUtil.calculateFingerprint(cert);
        } catch (CertificateException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        try {
            trustStore.getTrustedCertificate(fingerprint);
            log.info("Certificate '{}' already exists in the trusted store", fingerprint);
        } catch (KeyNotFoundException e) {
            try {
                trustStore.importTrustCertificate(cert, fingerprint);
                log.info("Certificate '{}' imported to trusted store", fingerprint);
            } catch (KeystoreException ee) {
                throw new RuntimeException(ee.getMessage(), ee);
            }
        } catch (KeystoreException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }


    private List<SecurityConfig.LdapServer> getLdapConfigurations() {
        final List<SecurityConfig.LdapServer> result = new ArrayList<>();
        for (LdapConfiguration cfg : ldapConfigurationManager.listLdapServerConfigurations()) {
            final SecurityConfig.LdapServer model = new SecurityConfig.LdapServer();
            model.name = cfg.getName();
            model.order = cfg.getOrder();
            final Connection conn = cfg.getConnection();
            if (conn != null) {
                model.connection = new SecurityConfig.LdapConnection();
                final Connection.Host host = conn.getHost();
                if (host != null) {
                    model.connection.protocol = SecurityConfig.LdapProtocol.valueOf(host.getProtocol().name());
                    model.connection.host = host.getHostName();
                    model.connection.port = host.getPort();
                }
                model.connection.searchBase = conn.getSearchBase();
                model.connection.authScheme = conn.getAuthScheme();
                model.connection.user = conn.getSystemUsername();
                model.connection.password = conn.getSystemPassword();
                model.connection.useTrustStore = conn.getUseTrustStore();
                model.connection.saslRealm = conn.getSaslRealm();
                model.connection.connectionTimeout = conn.getConnectionTimeout();
                model.connection.connectionRetryDelay = conn.getConnectionRetryDelay();
                model.connection.maxIncidentsCount = conn.getMaxIncidentsCount();
            }
            final Mapping mapping = cfg.getMapping();
            if (mapping != null) {
                model.mapping = new SecurityConfig.LdapMapping();
                model.mapping.userBaseDn = mapping.getUserBaseDn();
                model.mapping.userSubtree = mapping.isUserSubtree();
                model.mapping.userObjectClass = mapping.getUserObjectClass();
                model.mapping.userIdAttr = mapping.getUserIdAttribute();
                model.mapping.userNameAttr = mapping.getUserRealNameAttribute();
                model.mapping.userEmailAttr = mapping.getEmailAddressAttribute();
                model.mapping.userPasswordAttr = mapping.getUserPasswordAttribute();
                model.mapping.userMemberOfAttr = mapping.getUserMemberOfAttribute();
                model.mapping.ldapFilter = mapping.getLdapFilter();
                model.mapping.groupBaseDn = mapping.getGroupBaseDn();
                model.mapping.groupSubtree = mapping.isGroupSubtree();
                model.mapping.groupObjectClass = mapping.getGroupObjectClass();
                model.mapping.groupIdAttr = mapping.getGroupIdAttribute();
                model.mapping.groupMemberAttr = mapping.getGroupMemberAttribute();
                model.mapping.groupMemberFormat = mapping.getGroupMemberFormat();
                model.mapping.ldapGroupsAsRoles = mapping.isLdapGroupsAsRoles();
            }
            result.add(model);
        }
        return result;
    }

    private void updateLdapConfigurations(final List<SecurityConfig.LdapServer> configurations) {
        if (configurations == null) {
            return;
        }
        for (SecurityConfig.LdapServer model : configurations) {
            boolean changed = false;
            LdapConfiguration cfg;
            try {
                cfg = ldapConfigurationManager.getLdapServerConfigurationByName(model.name);
            } catch (LdapServerNotFoundException e) {
                cfg = ldapConfigurationManager.newConfiguration();
                cfg.setName(model.name);
                changed = true;
            }
            if (model.order != null && model.order != cfg.getOrder()) {
                cfg.setOrder(model.order);
                changed = true;
            }
            changed |= updateLdapConnection(cfg, model.connection);
            changed |= updateLdapMapping(cfg, model.mapping);
            if (changed) {
                if (cfg.getId() != null) {
                    log.debug("update existing ldap server {id:{}, name:{}} ...", cfg.getId(), cfg.getName());
                    try {
                        ldapConfigurationManager.updateLdapServerConfiguration(cfg);
                    } catch (LdapServerNotFoundException e) {
                        throw new RuntimeException(e.getMessage(), e);
                    }
                } else {
                    log.debug("add new ldap server '{}' ...", cfg.getName());
                    final String id = ldapConfigurationManager.addLdapServerConfiguration(cfg);
                    log.debug("added ldap server {}", id);
                }
            }
        }
    }

    private boolean updateLdapConnection(final LdapConfiguration cfg, final SecurityConfig.LdapConnection model) {
        if (model == null) {
            return false;
        }
        Connection conn = cfg.getConnection();
        if (conn == null) {
            conn = new Connection();
            cfg.setConnection(conn);
        }
        boolean changed = false;
        if (model.protocol != null || model.host != null || model.port != null) {
            Connection.Host host = conn.getHost();
            if (host == null) {
                host = new Connection.Host();
                conn.setHost(host);
            }
            if (model.protocol != null && (host.getProtocol() == null || !Objects.equals(model.protocol.name(), host.getProtocol().name()))) {
                host.setProtocol(Connection.Protocol.valueOf(model.protocol.name()));
                changed = true;
            }
            if (model.host != null && !model.host.equals(host.getHostName())) {
                host.setHostName(model.host);
                changed = true;
            }
            if (model.port != null && model.port != host.getPort()) {
                host.setPort(model.port);
                changed = true;
            }
        }
        if (model.searchBase != null && !model.searchBase.equals(conn.getSearchBase())) {
            conn.setSearchBase(model.searchBase);
            changed = true;
        }
        if (model.authScheme != null && !model.authScheme.equals(conn.getAuthScheme())) {
            conn.setAuthScheme(model.authScheme);
            changed = true;
        }
        if (model.user != null && !model.user.equals(conn.getSystemUsername())) {
            conn.setSystemUsername(model.user);
            changed = true;
        }
        if (model.password != null && !model.password.equals(conn.getSystemPassword())) {
            conn.setSystemPassword(model.password);
            changed = true;
        }
        if (model.useTrustStore != null && model.useTrustStore != conn.getUseTrustStore()) {
            conn.setUseTrustStore(model.useTrustStore);
            changed = true;
        }
        if (model.saslRealm != null && !model.saslRealm.equals(conn.getSaslRealm())) {
            conn.setSaslRealm(model.saslRealm);
            changed = true;
        }
        if (model.connectionTimeout != null && model.connectionTimeout != conn.getConnectionTimeout()) {
            conn.setConnectionTimeout(model.connectionTimeout);
            changed = true;
        }
        if (model.connectionRetryDelay != null && model.connectionRetryDelay != conn.getConnectionRetryDelay()) {
            conn.setConnectionRetryDelay(model.connectionRetryDelay);
            changed = true;
        }
        if (model.maxIncidentsCount != null && model.maxIncidentsCount != conn.getMaxIncidentsCount()) {
            conn.setMaxIncidentsCount(model.maxIncidentsCount);
            changed = true;
        }
        return changed;
    }

    private boolean updateLdapMapping(final LdapConfiguration cfg, final SecurityConfig.LdapMapping model) {
        if (model == null) {
            return false;
        }
        Mapping mapping = cfg.getMapping();
        if (mapping == null) {
            mapping = new Mapping();
            cfg.setMapping(mapping);
        }
        boolean changed = false;
        if (model.userBaseDn != null && !model.userBaseDn.equals(mapping.getUserBaseDn())) {
            mapping.setUserBaseDn(model.userBaseDn);
            changed = true;
        }
        if (model.userSubtree != null && model.userSubtree != mapping.isUserSubtree()) {
            mapping.setUserSubtree(model.userSubtree);
            changed = true;
        }
        if (model.userObjectClass != null && !model.userObjectClass.equals(mapping.getUserObjectClass())) {
            mapping.setUserObjectClass(model.userObjectClass);
            changed = true;
        }
        if (model.userIdAttr != null && !model.userIdAttr.equals(mapping.getUserIdAttribute())) {
            mapping.setUserIdAttribute(model.userIdAttr);
            changed = true;
        }
        if (model.userNameAttr != null && !model.userNameAttr.equals(mapping.getUserRealNameAttribute())) {
            mapping.setUserRealNameAttribute(model.userNameAttr);
            changed = true;
        }
        if (model.userEmailAttr != null && !model.userEmailAttr.equals(mapping.getEmailAddressAttribute())) {
            mapping.setEmailAddressAttribute(model.userEmailAttr);
            changed = true;
        }
        if (model.userPasswordAttr != null && !model.userPasswordAttr.equals(mapping.getUserPasswordAttribute())) {
            mapping.setUserPasswordAttribute(model.userPasswordAttr);
            changed = true;
        }
        if (model.userMemberOfAttr != null && !model.userMemberOfAttr.equals(mapping.getUserMemberOfAttribute())) {
            mapping.setUserMemberOfAttribute(model.userMemberOfAttr);
            changed = true;
        }
        if (model.ldapFilter != null && !model.ldapFilter.equals(mapping.getLdapFilter())) {
            mapping.setLdapFilter(model.ldapFilter);
            changed = true;
        }
        if (model.groupBaseDn != null && !model.groupBaseDn.equals(mapping.getGroupBaseDn())) {
            mapping.setGroupBaseDn(model.groupBaseDn);
            changed = true;
        }
        if (model.groupSubtree != null && model.groupSubtree != mapping.isGroupSubtree()) {
            mapping.setGroupSubtree(model.groupSubtree);
            changed = true;
        }
        if (model.groupObjectClass != null && !model.groupObjectClass.equals(mapping.getGroupObjectClass())) {
            mapping.setGroupObjectClass(model.groupObjectClass);
            changed = true;
        }
        if (model.groupIdAttr != null && !model.groupIdAttr.equals(mapping.getGroupIdAttribute())) {
            mapping.setGroupIdAttribute(model.groupIdAttr);
            changed = true;
        }
        if (model.groupMemberAttr != null && !model.groupMemberAttr.equals(mapping.getGroupMemberAttribute())) {
            mapping.setGroupMemberAttribute(model.groupMemberAttr);
            changed = true;
        }
        if (model.groupMemberFormat != null && !model.groupMemberFormat.equals(mapping.getGroupMemberFormat())) {
            mapping.setGroupMemberFormat(model.groupMemberFormat);
            changed = true;
        }
        if (model.ldapGroupsAsRoles != null && model.ldapGroupsAsRoles != mapping.isLdapGroupsAsRoles()) {
            mapping.setLdapGroupsAsRoles(model.ldapGroupsAsRoles);
            changed = true;
        }
        return changed;
    }


    private List<SecurityConfig.Realm> getRealms() {
        final List<SecurityConfig.Realm> result = new ArrayList<>();
        final List<String> enabledRealms = realmConfiguration.getRealmNames();
        for (SecurityRealm realm : realmManager.getAvailableRealms()) {
            final SecurityConfig.Realm model = new SecurityConfig.Realm();
            model.name = realm.getId();
            model.enabled = enabledRealms.contains(model.name);
            result.add(model);
        }
        return result;
    }

    private void updateRealms(final List<SecurityConfig.Realm> realms) {
        if (realms == null) {
            return;
        }
        final Set<String> availableRealms = realmManager.getAvailableRealms().stream()
                .map(SecurityRealm::getId)
                .collect(Collectors.toSet());
        for (SecurityConfig.Realm realm : realms) {
            if (!availableRealms.contains(realm.name)) {
                log.error("Unknown realm '{}'", realm.name);
                continue;
            }
            if (realm.enabled != null) {
                if (realm.enabled) {
                    log.info("Enabling realm {}", realm.name);
                    realmManager.enableRealm(realm.name);
                } else {
                    log.info("Disabling realm {}", realm.name);
                    realmManager.disableRealm(realm.name);
                }
            }
        }
    }


    private List<SecurityConfig.Privilege> getPrivileges(final Options opts) {
        final List<SecurityConfig.Privilege> result = new ArrayList<>();
        for (String authSource : securitySystem.listSources()) {
            final AuthorizationManager authManager = getAuthorizationManager(authSource);
            if (!authManager.supportsWrite() && !opts.showReadOnlyObjects) {
                continue;
            }
            final Set<Privilege> privileges = authManager.listPrivileges();
            if (privileges == null) {
                continue;
            }
            for (Privilege privilege : privileges) {
                if (privilege.isReadOnly() && !opts.showReadOnlyObjects) {
                    continue;
                }
                final SecurityConfig.Privilege model = new SecurityConfig.Privilege();
                model.authSource = authSource;
                model.id = privilege.getId();
                model.name = privilege.getName();
                model.type = privilege.getType();
                model.attrs = privilege.getProperties();
                model.readOnly = privilege.isReadOnly() || !authManager.supportsWrite();
                model.description = privilege.getDescription();
                result.add(model);
            }
        }
        return result;
    }

    private void updatePrivileges(final List<SecurityConfig.Privilege> privileges) {
        if (privileges == null) {
            return;
        }
        for (SecurityConfig.Privilege model : privileges) {
            if (model.id == null) {
                log.error("Can't process privilege: 'id' property is required");
                continue;
            }
            final AuthorizationManager authManager = getAuthorizationManager(model.authSource);
            try {
                final Privilege privilege = authManager.getPrivilege(model.id);
                final boolean readonlyPrivilege = privilege.isReadOnly() || !authManager.supportsWrite();
                boolean changed = false;
                if (model.name != null && !model.name.equals(privilege.getName())) {
                    privilege.setName(model.name);
                    changed = true;
                }
                if (model.description != null && !model.description.equals(privilege.getDescription())) {
                    privilege.setDescription(model.description);
                    changed = true;
                }
                if (model.type != null && !model.type.equals(privilege.getType())) {
                    privilege.setType(model.type);
                    changed = true;
                }
                final Map<String, String> oldAttrs = privilege.getProperties();
                if (model.attrs != null && (oldAttrs == null || !oldAttrs.equals(model.attrs))) {
                    privilege.setProperties(model.attrs);
                    changed = true;
                }
                if (changed) {
                    if (readonlyPrivilege) {
                        log.warn("Can't update readonly privilege {}. Operation skipped.", model.id);
                        continue;
                    }
                    log.info("Updating privilege {}", model.id);
                    authManager.updatePrivilege(privilege);
                }
            } catch (NoSuchPrivilegeException e) {
                if (authManager.supportsWrite()) {
                    log.info("Creating privilege {}", model.id);
                    final Privilege privilege = new Privilege(model.id, model.name, model.description, model.type, model.attrs, false);
                    authManager.addPrivilege(privilege);
                } else {
                    log.warn("Can't add privilege {} for {} source. Operation skipped.", model.id, model.authSource);
                }
            }
        }
    }

    private void deletePrivileges(final List<SecurityConfig.Key> keys) {
        if (keys == null) {
            return;
        }
        for (SecurityConfig.Key key : keys) {
            final AuthorizationManager authManager = getAuthorizationManager(key.authSource);
            try {
                if (!authManager.supportsWrite()) {
                    log.warn("Can't delete readonly privilege {}. Operation skipped.", key);
                    continue;
                }
                log.info("Deleting privilege {} (if exists)", key);
                authManager.deletePrivilege(key.id);
            } catch (NoSuchPrivilegeException e) {
                // do nothing
            }
        }
    }


    private List<SecurityConfig.Role> getRoles(final Options opts) {
        final List<SecurityConfig.Role> result = new ArrayList<>();
        for (Role role : securitySystem.listRoles()) {
            final AuthorizationManager authManager = getAuthorizationManager(role.getSource());
            final boolean readonlyRole = role.isReadOnly() || !authManager.supportsWrite();
            if (readonlyRole && !opts.showReadOnlyObjects) {
                continue;
            }
            final SecurityConfig.Role model = new SecurityConfig.Role();
            model.authSource = role.getSource();
            model.id = role.getRoleId();
            model.name = role.getName();
            model.description = role.getDescription();
            model.privileges = new ArrayList<>(role.getPrivileges());
            model.roles = new ArrayList<>(role.getRoles());
            model.readOnly = readonlyRole;
            result.add(model);
        }
        return result;
    }

    private void updateRoles(final List<SecurityConfig.Role> roles) {
        if (roles == null) {
            return;
        }
        for (SecurityConfig.Role model : roles) {
            final AuthorizationManager authManager = getAuthorizationManager(model.authSource);
            try {
                final Role role = authManager.getRole(model.id);
                final boolean readonlyRole = role.isReadOnly() || !authManager.supportsWrite();
                boolean changed = false;
                if (model.name != null && !model.name.equals(role.getName())) {
                    role.setName(model.name);
                    changed = true;
                }
                if (model.description != null && !model.description.equals(role.getDescription())) {
                    role.setDescription(model.description);
                    changed = true;
                }
                if (model.privileges != null && (role.getPrivileges() == null || model.privileges.size() != role.getPrivileges().size() || !role.getPrivileges().containsAll(model.privileges))) {
                    role.setPrivileges(new HashSet<>(model.privileges));
                    changed = true;
                }
                if (model.roles != null && (role.getRoles() == null || model.roles.size() != role.getRoles().size() || !role.getRoles().containsAll(model.roles))) {
                    role.setRoles(new HashSet<>(model.roles));
                    changed = true;
                }
                if (changed) {
                    if (readonlyRole) {
                        log.warn("Can't update readonly role {}. Operation skipped.", model.id);
                        continue;
                    }
                    log.info("Updating role {} ...", model.id);
                    authManager.updateRole(role);
                }
            } catch (NoSuchRoleException e) {
                if (authManager.supportsWrite()) {
                    final Set<String> includedPrivileges = model.privileges != null ? new HashSet<>(model.privileges) : new HashSet<>();
                    final Set<String> includedRoles = model.roles != null ? new HashSet<>(model.roles) : new HashSet<>();
                    final Role role = new Role(model.id, model.name, model.description, authManager.getSource(),
                            false, includedRoles, includedPrivileges);
                    log.info("Creating role {} ...", model.id);
                    authManager.addRole(role);
                } else {
                    log.warn("Can't add role {} for {} source. Operation skipped.", model.id, model.authSource);
                }
            }
        }
    }

    private void deleteRoles(final List<SecurityConfig.Key> keys) {
        if (keys == null) {
            return;
        }
        for (SecurityConfig.Key key : keys) {
            final AuthorizationManager authManager = getAuthorizationManager(key.authSource);
            try {
                if (!authManager.supportsWrite()) {
                    log.warn("Can't delete readonly role {}. Operation skipped.", key);
                    continue;
                }
                log.info("Deleting role {} (if exists) ...", key);
                authManager.deleteRole(key.id);
            } catch (NoSuchRoleException e) {
                // do nothing
            }
        }
    }


    private List<SecurityConfig.User> getUsers(final Options opts) {
        final List<SecurityConfig.User> result = new ArrayList<>();
        final UserSearchCriteria criteria = new UserSearchCriteria();
        final Set<User> users = securitySystem.searchUsers(criteria);
        for (User user : users) {
            final UserManager userManager;
            try {
                userManager = securitySystem.getUserManager(user.getSource());
            } catch (NoSuchUserManagerException e) {
                log.error("Can't resolve user manager for authorization source '" + user.getSource() + "' : " + e.getMessage(), e);
                throw new RuntimeException(e);
            }
            final boolean readOnlyUser = user.isReadOnly() || !userManager.supportsWrite();
            if (readOnlyUser && !opts.showReadOnlyObjects) {
                continue;
            }
            final SecurityConfig.User model = new SecurityConfig.User();
            model.authSource = user.getSource();
            model.id = user.getUserId();
            model.name = user.getName();
            model.firstName = user.getFirstName();
            model.lastName = user.getLastName();
            model.email = user.getEmailAddress();
            model.active = user.getStatus().isActive();
            model.roles = user.getRoles().stream().map(r -> new SecurityConfig.Key(r.getRoleId(), r.getSource())).collect(Collectors.toList());
            model.readOnly = readOnlyUser;
            result.add(model);
        }
        return result;
    }

    private void updateUsers(final List<SecurityConfig.User> users) {
        if (users == null) {
            return;
        }
        for (SecurityConfig.User model : users) {
            final SecurityConfig.Key key = new SecurityConfig.Key(model.id, model.authSource);
            try {
                final User user = model.authSource != null
                        ? securitySystem.getUser(model.id, model.authSource)
                        : securitySystem.getUser(model.id);
                log.info("User {} already exists. Checking for modifications ...", key);
                final UserManager userManager = securitySystem.getUserManager(user.getSource());
                final boolean readonlyUser = user.isReadOnly() || !userManager.supportsWrite();
                boolean changed = false;
                if (model.name != null && !model.name.equals(user.getName())) {
                    user.setName(model.name);
                    changed = true;
                }
                if (model.firstName != null && !model.firstName.equals(user.getFirstName())) {
                    user.setFirstName(model.firstName);
                    changed = true;
                }
                if (model.lastName != null && !model.lastName.equals(user.getLastName())) {
                    user.setLastName(model.lastName);
                    changed = true;
                }
                if (model.email != null && !model.email.equals(user.getEmailAddress())) {
                    user.setEmailAddress(model.email);
                    changed = true;
                }
                if (model.active != null && !Objects.equals(model.active, user.getStatus().isActive())) {
                    user.setStatus(model.active ? UserStatus.active : UserStatus.disabled);
                    changed = true;
                }
                final List<SecurityConfig.Key> oldRoles =
                        user.getRoles().stream()
                                .map(r -> new SecurityConfig.Key(r.getRoleId(), r.getSource()))
                                .collect(Collectors.toList());
                if (model.roles != null && (model.roles.size() != oldRoles.size() || !model.roles.containsAll(oldRoles))) {
                    user.setRoles(model.roles.stream().map(m -> new RoleIdentifier(m.authSource, m.id)).collect(Collectors.toSet()));
                    changed = true;
                }
                if (changed) {
                    if (readonlyUser) {
                        log.warn("Can't update readonly user {}. Operation skipped.", key);
                        continue;
                    }
                    log.info("Updating user {} ...", key);
                    securitySystem.updateUser(user);
                }
                if (model.updateExistingPassword != null && model.updateExistingPassword) {
                    if (readonlyUser) {
                        log.warn("Can't update password for readonly user {}. Operation skipped.", key);
                        continue;
                    }
                    try {
                        log.info("Updating user {} password ...", key);
                        ThreadContext.bind(FakeAlmightySubject.forUserId("nexus:*"));
                        securitySystem.changePassword(model.id, model.password);
                    } catch (UserNotFoundException e) {
                        log.error("Failed to update password of user " + key + ": " + e.getMessage(), e);
                        throw new RuntimeException(e.getMessage(), e);
                    } finally {
                        ThreadContext.remove();
                    }
                }
            } catch (NoSuchUserManagerException e) {
                log.error("Can't resolve authorization source '" + model.authSource + "' : " + e.getMessage(), e);
                throw new RuntimeException(e);
            } catch (UserNotFoundException e) {
                log.info("User {} does not yet exist. Creating it...", key);
                securityApi.addUser(
                        model.id,
                        model.firstName,
                        model.lastName,
                        model.email,
                        model.active != null && model.active,
                        model.password,
                        model.roles != null ? model.roles.stream().map(m -> m.id).collect(Collectors.toList()) : Collections.emptyList()
                );
            }
        }
    }

    private void deleteUsers(final List<SecurityConfig.Key> keys) {
        if (keys == null) {
            return;
        }
        for (SecurityConfig.Key key : keys) {
            try {
                final User user = key.authSource != null
                        ? securitySystem.getUser(key.id, key.authSource)
                        : securitySystem.getUser(key.id);
                final UserManager userManager = securitySystem.getUserManager(user.getSource());
                final boolean readonlyUser = user.isReadOnly() || !userManager.supportsWrite();
                if (readonlyUser) {
                    log.warn("Can't delete read only user {}. Operation skipped.", key);
                    continue;
                }
                log.info("Deleting user {} ...", key);
                securitySystem.deleteUser(user.getUserId(), user.getSource());
            } catch (NoSuchUserManagerException e) {
                log.warn("Can't resolve authorization source '{}'", key.authSource);
            } catch (UserNotFoundException e) {
                // do nothing
            }
        }
    }

    private void pruneOtherUsers(final Boolean pruneUsers, final List<SecurityConfig.User> allowedUsers) {
        if (pruneUsers == null || !pruneUsers) {
            return;
        }
        if (allowedUsers == null || allowedUsers.isEmpty()) {
            log.warn("securityConfig.pruneOtherUsers has no effect when no users are configured!");
            return;
        }
        final Set<String> allowedKeys = allowedUsers.stream().map(u -> u.id).collect(Collectors.toSet());
        final UserSearchCriteria criteria = new UserSearchCriteria();
        criteria.setSource(DEFAULT_AUTH_SOURCE);
        for (User user : securitySystem.searchUsers(criteria)) {
            if (allowedKeys.contains(user.getUserId())) {
                continue;
            }
            try {
                final UserManager userManager = securitySystem.getUserManager(user.getSource());
                final boolean readonlyUser = user.isReadOnly() || !userManager.supportsWrite();
                if (readonlyUser) {
                    log.warn("Can't delete read only user {id:{},src:{}}. Operation skipped.", user.getUserId(), user.getSource());
                    continue;
                }
                log.info("Deleting user {id:{}, source:{}} ...", user.getUserId(), user.getSource());
                securitySystem.deleteUser(user.getUserId(), user.getSource());
            } catch (NoSuchUserManagerException | UserNotFoundException e) {
                log.error(e.getMessage(), e);
            }
        }
    }


    private AuthorizationManager getAuthorizationManager(final String authSource) {
        try {
            return securitySystem.getAuthorizationManager(authSource != null ? authSource : DEFAULT_AUTH_SOURCE);
        } catch (NoSuchAuthorizationManagerException e) {
            log.error("Can't resolve authorization source '" + authSource + "' : " + e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }
}

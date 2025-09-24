package io.github.asharapov.nexus.casc.internal;

import io.github.asharapov.nexus.casc.internal.junit.IntegrationTest;
import io.github.asharapov.nexus.casc.internal.model.AnonymousAccessVO;
import io.github.asharapov.nexus.casc.internal.model.CertificateVO;
import io.github.asharapov.nexus.casc.internal.model.Config;
import io.github.asharapov.nexus.casc.internal.model.LdapServerVO;
import io.github.asharapov.nexus.casc.internal.model.PrivilegeVO;
import io.github.asharapov.nexus.casc.internal.model.RoleVO;
import io.github.asharapov.nexus.casc.internal.model.SecurityConfig;
import io.github.asharapov.nexus.casc.internal.model.UserVO;
import io.github.asharapov.nexus.casc.internal.utils.NexusAPI;
import io.github.asharapov.nexus.casc.internal.utils.NexusServer;
import io.github.asharapov.nexus.casc.internal.utils.OpenLDAPServer;
import io.github.asharapov.nexus.casc.internal.utils.TestUtils;
import io.qameta.allure.Description;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.opentest4j.AssertionFailedError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;
import retrofit2.Response;

import javax.inject.Inject;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import static io.github.asharapov.nexus.casc.internal.model.Config.ExecutionPolicy.ALWAYS;
import static io.github.asharapov.nexus.casc.internal.model.PrivilegeVO.Action.EDIT;
import static io.github.asharapov.nexus.casc.internal.model.PrivilegeVO.Action.READ;
import static io.github.asharapov.nexus.casc.internal.utils.TestUtils.call;
import static io.qameta.allure.Allure.step;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Testing the security configuration of the Sonatype Nexus.
 *
 * @author Anton Sharapov
 */
@IntegrationTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Tag("security")
public class SecurityConfigIT {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfigIT.class);

    @Inject
    private Yaml yaml;
    @Inject
    private OpenLDAPServer openLDAPServer;
    @Inject
    private NexusServer nexusServer;
    private NexusAPI api;

    public SecurityConfigIT() {
    }


    @BeforeEach
    void beforeEachTest() {
        api = nexusServer.getAdminAPI();
    }

    @Test
    @Order(1)
    @Description("Checking the CASC plugin API for enabling/disabling anonymous access to Sonatype Nexus")
    void testAnonymousAccess() {
        step("Create a new configuration with the disabled anonymous access and apply them on the server", () -> {
            final Config cfg = new Config(ALWAYS);
            cfg.securityConfig = new SecurityConfig();
            cfg.securityConfig.anonymousAccess = false;
            final boolean modified = applyNewConfiguration(cfg);
            assertTrue(modified, "The passed settings should be applied on the server");
        });
        step("Get the current configuration using CASC plugin API and check anonymous access status", () -> {
            final Config cfg = getCurrentConfiguration();
            assertNotNull(cfg.securityConfig);
            assertFalse(cfg.securityConfig.anonymousAccess, "Anonymous access should be disabled");
        });
        step("Check anonymous access status using standard Nexus API", () -> {
            final AnonymousAccessVO access = call(api.getAnonymousStatus());
            assertFalse(access.enabled, "Anonymous access should be disabled");
        });
    }


    @Test
    @Order(2)
    @Description("Checking the CASC plugin API for certificates importing into Nexus truststore")
    void testTrustStore() {
        step("Make sure that the Nexus truststore is empty by default", () -> {
            final List<CertificateVO> certs = call(api.getTrustedCertificates());
            assertNotNull(certs);
            assertTrue(certs.isEmpty(), "Nexus truststore is not empty");
        });
        step("Importing certificates from local files and servers on the Internet", () -> {
            final Config cfg = new Config(ALWAYS);
            cfg.securityConfig = new SecurityConfig();
            cfg.securityConfig.trustedCerts = new SecurityConfig.TrustedStore();
            cfg.securityConfig.trustedCerts.fromPEMFiles = Arrays.asList(
                    new URI("file:///opt/certs/www-postgresql-org-chain.pem"),
                    new URI("/opt/certs/www-redhat-com-chain.pem")
            );
            cfg.securityConfig.trustedCerts.fromServers = Arrays.asList(
                    new SecurityConfig.HostCertificate("www.oracle.com", 443),
                    new SecurityConfig.HostCertificate("www.google.com", 443)
            );
            final boolean modified = applyNewConfiguration(cfg);
            assertTrue(modified, "The passed settings should be applied on the server");
        });
        step("Checking the certificates installed in the Nexus truststore on the previous step", () -> {
            final List<CertificateVO> certs = call(api.getTrustedCertificates());
            assertNotNull(certs);
            assertTrue(
                    certs.stream().anyMatch(c -> c.subjectCommonName != null && c.subjectCommonName.contains(".postgresql.org")),
                    "Can't found postgresql.org certificate in the truststore");
            assertTrue(
                    certs.stream().anyMatch(c -> c.subjectCommonName != null && c.subjectCommonName.contains(".redhat.com")),
                    "Can't found redhat.com certificate in the truststore");
            assertTrue(
                    certs.stream().anyMatch(c -> c.subjectCommonName != null && c.subjectCommonName.contains(".oracle.com")),
                    "Can't found oracle.com certificate in the truststore");
            assertTrue(
                    certs.stream().anyMatch(c -> c.subjectCommonName != null && c.subjectCommonName.contains(".google.com")),
                    "Can't found google.com certificate in the truststore");
        });
    }


    @Test
    @Order(3)
    @Description("Checking the capabilities of the CASC plugin for privilege management")
    void testPrivileges() {
        final SecurityConfig.Privilege privilege = new SecurityConfig.Privilege();
        privilege.id = "system-repository-admin-docker-docker-proxy-update";
        privilege.name = "system-repository-admin-docker-docker-proxy-update";
        privilege.description = "Permit update to docker-proxy repository configuration";
        privilege.type = "repository-admin";
        privilege.attrs = new HashMap<>();
        privilege.attrs.put("format", "docker");
        privilege.attrs.put("repository", "docker-proxy");
        privilege.attrs.put("actions", "read,update");

        step("1. Checking the plugin's ability to register new privileges", () -> {
            step("Register new privilege", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.securityConfig = new SecurityConfig();
                cfg.securityConfig.privileges = Collections.singletonList(privilege);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Find registered privilege using CASC plugin API", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.securityConfig);
                assertNotNull(cfg.securityConfig.privileges);
                assertTrue(
                        cfg.securityConfig.privileges.stream().anyMatch(p -> {
                            return !p.readOnly &&
                                    privilege.id.equals(p.id) &&
                                    privilege.name.equals(p.name) &&
                                    privilege.description.equals(p.description) &&
                                    privilege.type.equals(p.type) &&
                                    privilege.attrs.equals(p.attrs);
                        }),
                        "Can't find registered privilege 'system-repository-admin-docker-docker-proxy-update'"
                );
            });
            step("Find registered privilege using standard Nexus API", () -> {
                final List<PrivilegeVO> privileges = call(api.getPrivileges());
                assertNotNull(privileges);
                assertTrue(
                        privileges.stream().anyMatch(p -> {
                            return !p.readOnly &&
                                    privilege.type.equals(p.type) &&
                                    "docker".equals(p.format) &&
                                    "docker-proxy".equals(p.repository) &&
                                    privilege.name.equals(p.name) &&
                                    privilege.description.equals(p.description) &&
                                    p.actions != null &&
                                    p.actions.size() == 2 &&
                                    p.actions.contains(READ) &&
                                    p.actions.contains(EDIT);
                        }),
                        "Can't find registered privilege 'system-repository-admin-docker-docker-proxy-update'"
                );
            });
        });
        step("2. Checking the plugin's ability to delete specified custom (where attribute 'readOnly' = false) privileges", () -> {
            step("Remove specified privileges using CASC plugin's API", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.securityConfig = new SecurityConfig();
                cfg.securityConfig.privilegesToDelete = Collections.singletonList(new SecurityConfig.Key(privilege.id, null));
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that the deleted yearly privilege are not exists", () -> {
                final List<PrivilegeVO> privileges = call(api.getPrivileges());
                assertNotNull(privileges);
                assertFalse(
                        privileges.stream().anyMatch(p -> {
                            return privilege.name.equals(p.name);
                        }),
                        "Deleted privilege '" + privilege.name + "' was found");
            });
        });
    }


    @Test
    @Order(4)
    @Description("Checking the capabilities of the CASC plugin for user role management")
    void testRoles() {
        final SecurityConfig.Role role1 = new SecurityConfig.Role("nx-developers", null);
        role1.name = "nx-developers";
        role1.description = "All developers";
        role1.privileges = Arrays.asList("nx-component-upload", "nx-repository-view-*-*-edit", "nx-repository-view-*-*-add");
        role1.roles = Collections.singletonList("nx-anonymous");
        role1.authSource = null;     // same as "default";

        final SecurityConfig.Role role2 = new SecurityConfig.Role("nx-test-role-1", "default");
        role2.name = "nx-test-role-1";
        role2.description = "For test purposes only";
        role2.roles = Collections.singletonList("nx-developers");

        final SecurityConfig.Role role3 = new SecurityConfig.Role("nx-test-role-2", "default");
        role3.name = "nx-test-role-2";
        role3.description = "For test purposes only";
        role3.roles = Collections.singletonList("nx-test-role-1");

        step("1. Checking the plugin's ability to register new roles", () -> {
            step("Registers a new roles that extends another role and has some additional privileges", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.securityConfig = new SecurityConfig();
                cfg.securityConfig.roles = Arrays.asList(role1, role2, role3);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Find registered roles using CASC plugin API", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.securityConfig);
                assertNotNull(cfg.securityConfig.roles);

                SecurityConfig.Role role = cfg.securityConfig.roles.stream()
                        .filter(r -> role1.id.equals(r.id))
                        .findAny()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered role '" + role1.id + "'"));
                assertEquals(role1.name, role.name, "Unexpected role name");
                assertEquals(role1.description, role.description, "Unexpected role description");
                assertNotNull(role.privileges, "No privileges for role found");
                assertTrue(role.privileges.containsAll(role1.privileges), "Expected privileges for the role were not found");
                assertNotNull(role.roles, "No inherited roles found");
                assertTrue(role.roles.containsAll(role1.roles), "No inherited roles found");
                assertEquals("default", role.authSource, "Unexpected role auth source");
                assertFalse(role.readOnly, "Unexpected role readonly status");

                role = cfg.securityConfig.roles.stream()
                        .filter(r -> role2.id.equals(r.id))
                        .findAny()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered role '" + role2.id + "'"));
                assertEquals(role2.name, role.name, "Unexpected role name");
                assertEquals(role2.description, role.description, "Unexpected role description");
                assertTrue(role.privileges != null && role.privileges.isEmpty(), "Unexpected privileges for role found");
                assertNotNull(role.roles, "No inherited roles found");
                assertTrue(role.roles.containsAll(role2.roles), "No inherited roles found");
                assertEquals("default", role.authSource, "Unexpected role auth source");
                assertFalse(role.readOnly, "Unexpected role readonly status");

                role = cfg.securityConfig.roles.stream()
                        .filter(r -> role3.id.equals(r.id))
                        .findAny()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered role '" + role3.id + "'"));
                assertEquals(role3.name, role.name, "Unexpected role name");
                assertEquals(role3.description, role.description, "Unexpected role description");
                assertTrue(role.privileges != null && role.privileges.isEmpty(), "Unexpected privileges for role found");
                assertNotNull(role.roles, "No inherited roles found");
                assertTrue(role.roles.containsAll(role3.roles), "No inherited roles found");
                assertEquals("default", role.authSource, "Unexpected role auth source");
                assertFalse(role.readOnly, "Unexpected role readonly status");
            });
            step("Find registered roles using standard Nexus API", () -> {
                final List<RoleVO> roles = call(api.getRoles("default"));
                assertNotNull(roles);
                RoleVO role = roles.stream()
                        .filter(r -> role1.id.equals(r.id))
                        .findAny()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered role '" + role1.id + "'"));
                assertEquals(role1.name, role.name, "Unexpected role name");
                assertEquals(role1.description, role.description, "Unexpected role description");
                assertNotNull(role.privileges, "No privileges for role found");
                assertTrue(role.privileges.containsAll(role1.privileges), "No privileges for role found");
                assertNotNull(role.roles, "No inherited roles found");
                assertTrue(role.roles.containsAll(role1.roles), "No inherited roles found");
                assertEquals("default", role.source, "Unexpected role auth source");

                role = roles.stream()
                        .filter(r -> role2.id.equals(r.id))
                        .findAny()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered role '" + role2.id + "'"));
                assertEquals(role2.name, role.name, "Unexpected role name");
                assertEquals(role2.description, role.description, "Unexpected role description");
                assertTrue(role.privileges != null && role.privileges.isEmpty(), "Unexpected privileges for role found");
                assertNotNull(role.roles, "No inherited roles found");
                assertTrue(role.roles.containsAll(role2.roles), "No inherited roles found");
                assertEquals("default", role.source, "Unexpected role auth source");

                role = roles.stream()
                        .filter(r -> role3.id.equals(r.id))
                        .findAny()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered role '" + role3.id + "'"));
                assertEquals(role3.name, role.name, "Unexpected role name");
                assertEquals(role3.description, role.description, "Unexpected role description");
                assertTrue(role.privileges != null && role.privileges.isEmpty(), "Unexpected privileges for role found");
                assertNotNull(role.roles, "No inherited roles found");
                assertTrue(role.roles.containsAll(role3.roles), "No inherited roles found");
                assertEquals("default", role.source, "Unexpected role auth source");
            });
        });
        step("2. Checking the plugin's ability to modify already existing roles", () -> {
            step("Modify the already existing test roles using CASC plugin API", () -> {
                final SecurityConfig.Role role31 = new SecurityConfig.Role(role3.id, "default");
                role31.name = role3.name + "-upd";
                role31.description = null;    // keep previous value of this property
                role31.privileges = Arrays.asList("nx-repository-view-*-*-edit", "nx-repository-view-*-*-add");
                role31.roles = null;          // keep previous value of this property
                final Config cfg = new Config(ALWAYS);
                cfg.securityConfig = new SecurityConfig();
                cfg.securityConfig.roles = Arrays.asList(
                        new SecurityConfig.Role(role2.id, role2.authSource),    // keep this role without any changes
                        role31  // modified version of the role3
                );
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Verify the changed role using standard Nexus API", () -> {
                final List<RoleVO> roles = call(api.getRoles("default"));
                assertNotNull(roles);
                RoleVO role = roles.stream()
                        .filter(r -> role2.id.equals(r.id))
                        .findAny()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered role '" + role2.id + "'"));
                assertEquals(role2.name, role.name, "Unexpected role name");
                assertEquals(role2.description, role.description, "Unexpected role description");
                assertTrue(role.privileges != null && role.privileges.isEmpty(), "Unexpected privileges for role found");
                assertNotNull(role.roles, "No inherited roles found");
                assertTrue(role.roles.containsAll(role2.roles), "No inherited roles found");
                assertEquals("default", role.source, "Unexpected role auth source");
                role = roles.stream()
                        .filter(r -> role3.id.equals(r.id))
                        .findAny()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered role '" + role3.id + "'"));
                assertEquals(role3.name + "-upd", role.name, "Unexpected role name");
                assertEquals(role3.description, role.description, "Unexpected role description");
                assertNotNull(role.privileges, "No expected privileges");
                assertTrue(role.privileges.size() == 2 && role.privileges.containsAll(Arrays.asList("nx-repository-view-*-*-edit", "nx-repository-view-*-*-add")), "Unexpected privileges for role found");
                assertNotNull(role.roles, "No inherited roles found");
                assertTrue(role.roles.containsAll(role3.roles), "No inherited roles found");
                assertEquals("default", role.source, "Unexpected role auth source");
            });
        });
        step("3. Checks whether a role that links to an unknown role cannot be registered", () -> {
            final Config cfg = new Config(ALWAYS);
            cfg.securityConfig = new SecurityConfig();
            cfg.securityConfig.roles = new ArrayList<>();
            final SecurityConfig.Role role = new SecurityConfig.Role();
            cfg.securityConfig.roles.add(role);
            role.id = "nx-test-role";
            role.name = "nx-test-role";
            role.description = "For test purposes only";
            role.roles = Arrays.asList("nx-unknown-role", "nx-anonymous");
            assertThrows(Throwable.class, () -> applyNewConfiguration(cfg));
            final List<RoleVO> roles = call(api.getRoles("default"));
            assertFalse(
                    roles.stream().anyMatch(r -> "nx-test-role".equals(r.id)),
                    "Unexpected role 'nx-test-role' found");
        });
        step("4. Checks whether a role that links to an unknown privilege cannot be registered", () -> {
            final Config cfg = new Config(ALWAYS);
            cfg.securityConfig = new SecurityConfig();
            cfg.securityConfig.roles = new ArrayList<>();
            final SecurityConfig.Role role = new SecurityConfig.Role();
            cfg.securityConfig.roles.add(role);
            role.id = "nx-test-role";
            role.name = "nx-test-role";
            role.description = "For test purposes only";
            role.privileges = Arrays.asList("nx-component-unknownaction", "nx-repository-view-*-*-edit");
            assertThrows(Throwable.class, () -> applyNewConfiguration(cfg));
            final List<RoleVO> roles = call(api.getRoles("default"));
            assertFalse(
                    roles.stream().anyMatch(r -> "nx-test-role".equals(r.id)),
                    "Unexpected role 'nx-test-role' found");
        });
        step("5. Checking the plugin's ability to delete specified user roles", () -> {
            step("Remove specified roles using CASC plugin's API", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.securityConfig = new SecurityConfig();
                cfg.securityConfig.rolesToDelete = Arrays.asList(
                        new SecurityConfig.Key(role2.id, null),         // null authSource is same as "default"
                        new SecurityConfig.Key(role3.id, "default"));
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that the deleted yearly test roles are not exists", () -> {
                final List<RoleVO> roles = call(api.getRoles("default"));
                assertTrue(
                        roles.stream().anyMatch(r -> role1.id.equals(r.id)),
                        "No role '" + role1.id + "' was found");
                assertFalse(
                        roles.stream().anyMatch(r -> role2.id.equals(r.id)),
                        "Deleted role '" + role2.id + "' was found");
                assertFalse(
                        roles.stream().anyMatch(r -> role3.id.equals(r.id)),
                        "Deleted role '" + role3.id + "' was found");
            });
        });
    }


    @Test
    @Order(5)
    @Description("Checking the capabilities of the CASC plugin for user management using 'default' realm")
    void testUsers() {
        final SecurityConfig.Role role1 = new SecurityConfig.Role("nx-developers", "default");
        role1.name = "nx-developers";
        role1.description = "All developers";
        role1.privileges = Arrays.asList("nx-component-upload", "nx-repository-view-*-*-edit", "nx-repository-view-*-*-add");
        role1.roles = Collections.singletonList("nx-anonymous");

        final SecurityConfig.User user1 = new SecurityConfig.User("jdoe", null);
        user1.name = "John Doe";
        user1.firstName = "John";
        user1.lastName = "Doe";
        user1.email = "jdoe@mail.com";
        user1.active = true;
        user1.roles = Collections.singletonList(new SecurityConfig.Key("nx-anonymous", "default"));
        user1.password = "jdoe123";
        user1.updateExistingPassword = true;

        final SecurityConfig.User user2 = new SecurityConfig.User("rroe", null);
        user2.name = "Richard Roe";
        user2.firstName = "Richard";
        user2.lastName = "Roe";
        user2.email = "richardroe@mail.com";
        user2.active = true;
        user2.roles = Collections.singletonList(new SecurityConfig.Key("nx-anonymous", "default"));
        user2.password = "rroe123";
        user2.updateExistingPassword = true;

        final SecurityConfig.User user3 = new SecurityConfig.User("jdaniels", "default");
        user3.name = "Jack Daniels";
        user3.firstName = "Jack";
        user3.lastName = "Daniels";
        user3.email = "jdaniels@mail.com";
        user3.roles = Collections.singletonList(new SecurityConfig.Key("nx-developers", null));
        user3.password = "jdanxxx";

        step("1. Checking the plugin's ability to register new users", () -> {
            step("Registering two test users using CASC plugin API", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.securityConfig = new SecurityConfig();
                cfg.securityConfig.roles = Collections.singletonList(role1);
                cfg.securityConfig.users = Arrays.asList(user1, user2, user3);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Find registered test users using CASC plugin API", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.securityConfig);
                assertNotNull(cfg.securityConfig.users);
                SecurityConfig.User user = cfg.securityConfig.users.stream()
                        .filter(u -> user1.id.equals(u.id))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered user '" + user1.id + "'"));
                assertEquals(user1.name, user.name, "Unexpected user name");
                assertEquals(user1.firstName, user.firstName, "Unexpected user firstName");
                assertEquals(user1.lastName, user.lastName, "Unexpected user lastName");
                assertEquals(user1.email, user.email, "Unexpected user email");
                assertEquals(user1.active != null && user1.active, user.active, "Unexpected user status");
                assertEquals(user1.roles, user.roles, "Unexpected user roles");
                user = cfg.securityConfig.users.stream()
                        .filter(u -> user2.id.equals(u.id))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered user '" + user2.id + "'"));
                assertEquals(user2.name, user.name, "Unexpected user name");
                assertEquals(user2.firstName, user.firstName, "Unexpected user firstName");
                assertEquals(user2.lastName, user.lastName, "Unexpected user lastName");
                assertEquals(user2.email, user.email, "Unexpected user email");
                assertEquals(user2.active != null && user2.active, user.active, "Unexpected user status");
                assertEquals(user2.roles, user.roles, "Unexpected user roles");
                user = cfg.securityConfig.users.stream()
                        .filter(u -> user3.id.equals(u.id))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered user '" + user3.id + "'"));
                assertEquals(user3.name, user.name, "Unexpected user name");
                assertEquals(user3.firstName, user.firstName, "Unexpected user firstName");
                assertEquals(user3.lastName, user.lastName, "Unexpected user lastName");
                assertEquals(user3.email, user.email, "Unexpected user email");
                assertEquals(user3.active != null && user3.active, user.active, "Unexpected user status");
                assertTrue(user.roles.size() == 1 &&
                                "nx-developers".equals(user.roles.get(0).id) &&
                                "default".equals(user.roles.get(0).authSource),
                        "Unexpected user roles");
            });
            step("Find registered test users using standard Nexus API", () -> {
                final List<UserVO> users = call(api.getUsers("default", null));
                assertNotNull(users);
                UserVO user = users.stream()
                        .filter(u -> user1.id.equals(u.userId))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered user '" + user1.id + "'"));
                assertEquals(user1.firstName, user.firstName, "Unexpected user firstName");
                assertEquals(user1.lastName, user.lastName, "Unexpected user lastName");
                assertEquals(user1.email, user.emailAddress, "Unexpected user email");
                assertEquals(user1.active != null && user1.active, user.status == UserVO.Status.active || user.status == UserVO.Status.changepassword, "Unexpected user status");
                assertTrue(user1.roles.size() == user.roles.size() &&
                                user1.roles.stream().map(k -> k.id).collect(Collectors.toSet()).containsAll(user.roles),
                        "Unexpected user roles");
                user = users.stream()
                        .filter(u -> user2.id.equals(u.userId))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered user '" + user2.id + "'"));
                assertEquals(user2.firstName, user.firstName, "Unexpected user firstName");
                assertEquals(user2.lastName, user.lastName, "Unexpected user lastName");
                assertEquals(user2.email, user.emailAddress, "Unexpected user email");
                assertEquals(user2.active != null && user2.active, user.status == UserVO.Status.active || user.status == UserVO.Status.changepassword, "Unexpected user status");
                assertTrue(user2.roles.size() == user.roles.size() &&
                                user2.roles.stream().map(k -> k.id).collect(Collectors.toSet()).containsAll(user.roles),
                        "Unexpected user roles");
                user = users.stream()
                        .filter(u -> user3.id.equals(u.userId))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered user '" + user3.id + "'"));
                assertEquals(user3.firstName, user.firstName, "Unexpected user firstName");
                assertEquals(user3.lastName, user.lastName, "Unexpected user lastName");
                assertEquals(user3.email, user.emailAddress, "Unexpected user email");
                assertEquals(user3.active != null && user3.active, user.status == UserVO.Status.active || user.status == UserVO.Status.changepassword, "Unexpected user status");
                assertTrue(user.roles.size() == 1 && "nx-developers".equals(user.roles.get(0)), "Unexpected user roles");
            });
        });
        step("2. Checking the plugin's ability to modify already existing users", () -> {
            step("Modify the already existing test user using CASC plugin API", () -> {
                final SecurityConfig.User user11 = new SecurityConfig.User(user1.id, user1.authSource);
                user11.name = "Judy Doe";
                user11.firstName = "Judy";
                user11.roles = Collections.singletonList(new SecurityConfig.Key("nx-developers", "default"));
                user11.password = "ju321";
                user11.updateExistingPassword = true;
                final Config cfg = new Config(ALWAYS);
                cfg.securityConfig = new SecurityConfig();
                cfg.securityConfig.users = Collections.singletonList(user11);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Verify the changed user using standard Nexus API", () -> {
                final List<UserVO> users = call(api.getUsers("default", null));
                assertNotNull(users);
                UserVO user = users.stream()
                        .filter(u -> user1.id.equals(u.userId))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered user '" + user1.id + "'"));
                assertEquals("Judy", user.firstName, "Unexpected user firstName");
                assertEquals(user1.lastName, user.lastName, "Unexpected user lastName");
                assertEquals(user1.email, user.emailAddress, "Unexpected user email");
                assertEquals(user1.active, user.status == UserVO.Status.active || user.status == UserVO.Status.changepassword, "Unexpected user status");
                assertTrue(user.roles.size() == 1 && user.roles.contains("nx-developers"), "Unexpected user roles");
            });
        });
        step("3. Checking the plugin's ability to delete specified users", () -> {
            step("Check existing test users using standard Nexus API", () -> {
                final List<UserVO> users = call(api.getUsers("default", null));
                assertTrue(
                        users.stream().anyMatch(u -> user1.id.equals(u.userId)),
                        "No user '" + user1.id + "' found");
                assertTrue(
                        users.stream().anyMatch(u -> user2.id.equals(u.userId)),
                        "No user '" + user2.id + "' found");
                assertTrue(
                        users.stream().anyMatch(u -> user3.id.equals(u.userId)),
                        "No user '" + user3.id + "' found");
            });
            step("Remove specified users using CASC plugin's API", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.securityConfig = new SecurityConfig();
                cfg.securityConfig.usersToDelete = Arrays.asList(
                        new SecurityConfig.Key("jdoe", null),
                        new SecurityConfig.Key("rroe", "default")
                );
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that the specified users no longer exist", () -> {
                final List<UserVO> users = call(api.getUsers("default", null));
                assertFalse(
                        users.stream().anyMatch(u -> user1.id.equals(u.userId)),
                        "Deleted user '" + user1.id + "' found");
                assertFalse(
                        users.stream().anyMatch(u -> user2.id.equals(u.userId)),
                        "Deleted user '" + user2.id + "' found");
                assertTrue(
                        users.stream().anyMatch(u -> user3.id.equals(u.userId)),
                        "No user '" + user3.id + "' found");
            });
        });
        step("4. Check the plugin's ability to delete all users except those listed", () -> {
            step("Add more test users", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.securityConfig = new SecurityConfig();
                cfg.securityConfig.users = Arrays.asList(user1, user2);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Check existing users", () -> {
                final Config cfg = getCurrentConfiguration();
                final Collection<String> expectedUsers = Arrays.asList(
                        "anonymous", "admin",            // default Nexus users
                        "jdoe", "rroe", "jdaniels"       // our test users
                );
                assertEquals(
                        expectedUsers.size(),
                        cfg.securityConfig.users.stream().filter(u -> expectedUsers.contains(u.id)).count(),
                        "Expected users not found");
            });
            step("Prune all users except 'admin' and 'anonymous' from the server", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.securityConfig = new SecurityConfig();
                cfg.securityConfig.users = Arrays.asList(           // keep that users without any changes
                        new SecurityConfig.User("admin", null),
                        new SecurityConfig.User("anonymous", null)
                );
                cfg.securityConfig.pruneOtherUsers = true;               // prunes all other users from server
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that all unnecessary users are deleted", () -> {
                final Config cfg = getCurrentConfiguration();
                final Collection<String> expectedUsers = Arrays.asList("anonymous", "admin");
                assertEquals(expectedUsers.size(), cfg.securityConfig.users.size(), "Unexpected users count on the server");
                assertEquals(
                        expectedUsers.size(),
                        cfg.securityConfig.users.stream().filter(u -> expectedUsers.contains(u.id)).count(),
                        "Expected users not found");
            });
        });
    }


    @Test
    @Order(6)
    @Description("Settings of the LDAP connections")
    @Tag("ldap")
    void testLdapIntegration() {
        final SecurityConfig.LdapConnection conn = new SecurityConfig.LdapConnection();
        String password = "admin123";
        conn.protocol = SecurityConfig.LdapProtocol.ldap;
        conn.host = openLDAPServer.getInternalIPAddress();  // Nexus consider the host name automatically generated by the docker to be incorrect
        conn.port = 389;
        conn.searchBase = "dc=example,dc=org";
        conn.authScheme = "simple";
        conn.user = "cn=admin,dc=example,dc=org";
        conn.password = password;
        conn.useTrustStore = false;
        conn.connectionRetryDelay = 300;
        conn.connectionTimeout = 30;
        conn.maxIncidentsCount = 3;

        final SecurityConfig.LdapMapping mapping = new SecurityConfig.LdapMapping();
        mapping.userBaseDn = "ou=users";
        mapping.userSubtree = true;
        mapping.userObjectClass = "person";
        mapping.userIdAttr = "cn";
        mapping.userNameAttr = "displayName";
        mapping.userEmailAttr = "mail";
        mapping.userPasswordAttr = "userPassword";
        mapping.ldapFilter = "";
        mapping.groupBaseDn = "ou=groups";
        mapping.groupSubtree = true;
        mapping.groupObjectClass = "posixGroup";
        mapping.groupIdAttr = "cn";
        mapping.groupMemberAttr = "member";
        mapping.groupMemberFormat = "cn=${username},ou=users,dc=example,dc=org";
        mapping.ldapGroupsAsRoles = true;
        mapping.userMemberOfAttr = null;

        final SecurityConfig.LdapServer server1 = new SecurityConfig.LdapServer();
        server1.name = "openldap";
        server1.connection = conn;
        server1.mapping = mapping;
        server1.order = 0;

        step("Make sure that the LDAP settings are not configured yet and the LDAP realm is disabled", () -> {
            final Config cfg = getCurrentConfiguration(true);
            assertNotNull(cfg.securityConfig);
            assertTrue(cfg.securityConfig.ldapServers == null || cfg.securityConfig.ldapServers.isEmpty(), "Unexpected ldap servers registered");
            assertNotNull(cfg.securityConfig.realms);
            final SecurityConfig.Realm realm = cfg.securityConfig.realms.stream()
                    .filter(r -> "LdapRealm".equals(r.name))
                    .findAny()
                    .orElseThrow(() -> new AssertionFailedError("Can't find standard realm 'LdapRealm'"));
            assertFalse(realm.enabled, "LdapRealm should be disabled if no configured ldap servers exists");
        });
        step("Registering LDAP connection using CASC plugin's API", () -> {
            final Config cfg = new Config(ALWAYS);
            cfg.securityConfig = new SecurityConfig();
            cfg.securityConfig.ldapServers = Collections.singletonList(server1);
            assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
        });
        step("Find registered LDAP connection using CASC plugin API", () -> {
            final Config cfg = getCurrentConfiguration();
            assertNotNull(cfg.securityConfig);
            assertNotNull(cfg.securityConfig.ldapServers);
            assertEquals(1, cfg.securityConfig.ldapServers.size(), "Unexpected ldap servers count");
            final SecurityConfig.LdapServer srv = cfg.securityConfig.ldapServers.get(0);
            assertEquals(server1.name, srv.name, "Unexpected ldap server name");
            assertEquals(server1.order, srv.order, "Unexpected ldap server order");
            assertEquals(server1.connection.protocol, srv.connection.protocol, "Unexpected ldap server protocol");
            assertEquals(server1.connection.host, srv.connection.host, "Unexpected ldap server host");
            assertEquals(server1.connection.port, srv.connection.port, "Unexpected ldap server port");
            assertEquals(server1.connection.searchBase, srv.connection.searchBase, "Unexpected ldap server search base DN");
            assertEquals(server1.connection.authScheme, srv.connection.authScheme, "Unexpected ldap server auth scheme");
            assertEquals(server1.connection.user, srv.connection.user, "Unexpected ldap server user");
            assertEquals(server1.connection.password, srv.connection.password, "Unexpected ldap server user password");
            assertEquals(server1.connection.useTrustStore, srv.connection.useTrustStore, "Unexpected ldap server trust store usage");
            assertEquals(server1.connection.connectionRetryDelay, srv.connection.connectionRetryDelay, "Unexpected ldap server connection retry");
            assertEquals(server1.connection.connectionTimeout, srv.connection.connectionTimeout, "Unexpected ldap server connection timeout");
            assertEquals(server1.connection.maxIncidentsCount, srv.connection.maxIncidentsCount, "Unexpected ldap server connection max incidents count");
            assertEquals(server1.mapping.userBaseDn, srv.mapping.userBaseDn, "Unexpected ldap server user base DN");
            assertEquals(server1.mapping.userSubtree, srv.mapping.userSubtree, "Unexpected ldap server user subtree flag");
            assertEquals(server1.mapping.userObjectClass, srv.mapping.userObjectClass, "Unexpected ldap server user object class");
            assertEquals(server1.mapping.userIdAttr, srv.mapping.userIdAttr, "Unexpected ldap server user id attr");
            assertEquals(server1.mapping.userNameAttr, srv.mapping.userNameAttr, "Unexpected ldap server user name attr");
            assertEquals(server1.mapping.userEmailAttr, srv.mapping.userEmailAttr, "Unexpected ldap server user email attr");
            assertEquals(server1.mapping.userPasswordAttr, srv.mapping.userPasswordAttr, "Unexpected ldap server user password attr");
            assertEquals(server1.mapping.ldapFilter, srv.mapping.ldapFilter, "Unexpected ldap server ldap filter");
            assertEquals(server1.mapping.groupBaseDn, srv.mapping.groupBaseDn, "Unexpected ldap group base DN");
            assertEquals(server1.mapping.groupSubtree, srv.mapping.groupSubtree, "Unexpected ldap group subtree");
            assertEquals(server1.mapping.groupObjectClass, srv.mapping.groupObjectClass, "Unexpected ldap group object class");
            assertEquals(server1.mapping.groupIdAttr, srv.mapping.groupIdAttr, "Unexpected ldap group object class");
            assertEquals(server1.mapping.groupMemberAttr, srv.mapping.groupMemberAttr, "Unexpected ldap group id attr");
            assertEquals(server1.mapping.groupMemberFormat, srv.mapping.groupMemberFormat, "Unexpected ldap group member attr");
            assertEquals(server1.mapping.ldapGroupsAsRoles, srv.mapping.ldapGroupsAsRoles, "Unexpected ldap ldapGroupsAsRoles flag");
            assertEquals(server1.mapping.userMemberOfAttr, srv.mapping.userMemberOfAttr, "Unexpected ldap userMemberOfAttr");
            assertNotNull(cfg.securityConfig.realms);
            final SecurityConfig.Realm realm = cfg.securityConfig.realms.stream()
                    .filter(r -> "LdapRealm".equals(r.name))
                    .findAny()
                    .orElseThrow(() -> new AssertionFailedError("Can't find standard realm 'LdapRealm'"));
            assertTrue(realm.enabled, "LdapRealm should be automatically enabled if configured ldap servers exists");
        });
        step("Find registered LDAP connection using standard Nexus REST API", () -> {
            final List<LdapServerVO> servers = call(api.getLdapServers());
            assertNotNull(servers);
            assertEquals(1, servers.size(), "unexpected ldap servers count");
            final LdapServerVO srv = servers.get(0);
            assertNotNull(srv);
            assertEquals(server1.name, srv.name, "Unexpected ldap server name");
            assertEquals(server1.connection.protocol.name().toUpperCase(), srv.protocol.name().toUpperCase(), "Unexpected ldap server protocol");
            assertEquals(server1.connection.host, srv.host, "Unexpected ldap server host");
            assertEquals(server1.connection.port, srv.port, "Unexpected ldap server port");
            assertEquals(server1.connection.searchBase, srv.searchBase, "Unexpected ldap server search base DN");
            assertEquals(server1.connection.authScheme.toUpperCase(), srv.authScheme.toUpperCase(), "Unexpected ldap server auth scheme");
            assertEquals(server1.connection.user, srv.authUsername, "Unexpected ldap server user");
            assertEquals(server1.connection.useTrustStore, srv.useTrustStore, "Unexpected ldap server trust store usage");
            assertEquals(server1.connection.connectionRetryDelay, srv.connectionRetryDelaySeconds, "Unexpected ldap server connection retry");
            assertEquals(server1.connection.connectionTimeout, srv.connectionTimeoutSeconds, "Unexpected ldap server connection timeout");
            assertEquals(server1.connection.maxIncidentsCount, srv.maxIncidentsCount, "Unexpected ldap server connection max incidents count");
            assertEquals(server1.mapping.userBaseDn, srv.userBaseDn, "Unexpected ldap server user base DN");
            assertEquals(server1.mapping.userSubtree, srv.userSubtree, "Unexpected ldap server user subtree flag");
            assertEquals(server1.mapping.userObjectClass, srv.userObjectClass, "Unexpected ldap server user object class");
            assertEquals(server1.mapping.userIdAttr, srv.userIdAttribute, "Unexpected ldap server user id attr");
            assertEquals(server1.mapping.userNameAttr, srv.userRealNameAttribute, "Unexpected ldap server user name attr");
            assertEquals(server1.mapping.userEmailAttr, srv.userEmailAddressAttribute, "Unexpected ldap server user email attr");
            assertEquals(server1.mapping.userPasswordAttr, srv.userPasswordAttribute, "Unexpected ldap server user password attr");
            assertEquals(server1.mapping.ldapFilter, srv.userLdapFilter, "Unexpected ldap server ldap filter");
            assertEquals(server1.mapping.groupBaseDn, srv.groupBaseDn, "Unexpected ldap group base DN");
            assertEquals(server1.mapping.groupSubtree, srv.groupSubtree, "Unexpected ldap group subtree");
            assertEquals(server1.mapping.groupObjectClass, srv.groupObjectClass, "Unexpected ldap group object class");
            assertEquals(server1.mapping.groupIdAttr, srv.groupIdAttribute, "Unexpected ldap group object class");
            assertEquals(server1.mapping.groupMemberAttr, srv.groupMemberAttribute, "Unexpected ldap group id attr");
            assertEquals(server1.mapping.groupMemberFormat, srv.groupMemberFormat, "Unexpected ldap group member attr");
            assertEquals(server1.mapping.ldapGroupsAsRoles, srv.ldapGroupsAsRoles, "Unexpected ldap ldapGroupsAsRoles flag");
            assertEquals(server1.mapping.userMemberOfAttr, srv.userMemberOfAttribute, "Unexpected ldap userMemberOfAttr");
            final List<String> activeRealmIds = call(api.getActiveRealmIds());
            assertNotNull(activeRealmIds);
            assertTrue(activeRealmIds.contains("LdapRealm"), "LdapRealm should be automatically enabled if configured ldap servers exists");
        });
        step("Map external users from LDAP group 'staff' to new Nexus role 'nx-staff'", () -> {
            final SecurityConfig.Role role = new SecurityConfig.Role("staff", "default");
            role.name = "nx-staff";
            role.description = "Map external developers from LDAP group 'staff' to Nexus role 'nx-staff'";
            role.privileges = Collections.singletonList("nx-component-upload");
            role.roles = Collections.singletonList("nx-anonymous");
            final Config cfg = new Config(ALWAYS);
            cfg.securityConfig = new SecurityConfig();
            cfg.securityConfig.roles = Collections.singletonList(role);
            assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
        });
        step("Make sure that all users registered in LDAP server and included in the group 'staff' are now accessible from Nexus", () -> {
            final Config cfg = getCurrentConfiguration(true);
            assertNotNull(cfg.securityConfig.users);
            final List<SecurityConfig.User> externalUsers = cfg.securityConfig.users.stream()
                    .filter(u -> "LDAP".equals(u.authSource))
                    .collect(Collectors.toList());
            assertTrue(externalUsers.size() > 0, "No expected external users found");
        });
    }


    @Test
    @Order(7)
    @Description("Testing access rights for the CASC plugin REST API")
    void testCascAPIAccess() {
        step("Make sure that CASC plugin REST API are not available for unauthorized users", () -> {
            final NexusAPI api = nexusServer.getAPI(null, null);
            step("Testing 'GET /casc/config' ...", () -> {
                final retrofit2.Response<ResponseBody> response = api.getConfiguration().execute();
                assertFalse(response.isSuccessful(), "Unauthorized API call must fail");
                assertTrue(response.code()==401 || response.code() == 403, "Unexpected API result code");
            });
            step("Testing 'PUT /casc/config' ...", () -> {
                final RequestBody reqBody = RequestBody.create(TestUtils.YAML_TYPE, yaml.dump(new Config(ALWAYS)));
                final Response<ResponseBody> response = api.applyConfiguration(reqBody).execute();
                assertFalse(response.isSuccessful(), "Unauthorized API call must fail");
                assertTrue(response.code()==401 || response.code() == 403, "Unexpected API result code");
            });
        });
        step("Make sure that the CASC plugin REST API is not available to any Sonatype Nexus users who hasn't administrator's rights", () -> {
            step("Test user registration", () -> {
                final SecurityConfig.Role role = new SecurityConfig.Role("nx-developers", "default");
                role.name = "nx-developers";
                role.description = "All developers";
                role.privileges = Arrays.asList("nx-component-upload", "nx-repository-view-*-*-edit", "nx-repository-view-*-*-add");
                role.roles = Collections.singletonList("nx-anonymous");

                final SecurityConfig.User user = new SecurityConfig.User("jdoe", "default");
                user.name = "John Doe";
                user.firstName = "John";
                user.lastName = "Doe";
                user.email = "jdoe@mail.com";
                user.active = true;
                user.roles = Arrays.asList(
                        new SecurityConfig.Key("nx-anonymous", "default"),
                        new SecurityConfig.Key("nx-developers", "default")
                );
                user.password = "jdoe123";
                user.updateExistingPassword = true;

                final Config cfg = new Config(ALWAYS);
                cfg.securityConfig = new SecurityConfig();
                cfg.securityConfig.roles = Collections.singletonList(role);
                cfg.securityConfig.users = Collections.singletonList(user);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            final NexusAPI api = nexusServer.getAPI("jdoe", "jdoe123");
            step("Testing 'GET /casc/config' ...", () -> {
                final retrofit2.Response<ResponseBody> response = api.getConfiguration().execute();
                assertFalse(response.isSuccessful(), "Unauthorized API call must fail");
                assertEquals(403, response.code(), "Unexpected API result code");
            });
            step("Testing 'PUT /casc/config' ...", () -> {
                final RequestBody reqBody = RequestBody.create(TestUtils.YAML_TYPE, yaml.dump(new Config(ALWAYS)));
                final Response<ResponseBody> response = api.applyConfiguration(reqBody).execute();
                assertFalse(response.isSuccessful(), "Unauthorized API call must fail");
                assertEquals(403, response.code(), "Unexpected API result code");
            });
        });
        step("Make sure that the CASC plugin REST API is available to Sonatype Nexus users who has administrator's rights", () -> {
            step("Grant administrators permissions to user", () -> {
                final SecurityConfig.Role role = new SecurityConfig.Role("nx-mycompany-superusers", "default");
                role.name = "nx-mycompany-superusers";
                role.description = "Sonatype Nexus administrators team";
                role.privileges = Collections.singletonList("nx-all");

                final SecurityConfig.User user = new SecurityConfig.User("jdoe", "default");
                user.name = "John Doe";
                user.firstName = "John";
                user.lastName = "Doe";
                user.email = "jdoe@mail.com";
                user.active = true;
                user.roles = Collections.singletonList(new SecurityConfig.Key("nx-mycompany-superusers", "default"));
                user.password = "jdoe123";
                user.updateExistingPassword = true;

                final Config cfg = new Config(ALWAYS);
                cfg.securityConfig = new SecurityConfig();
                cfg.securityConfig.roles = Collections.singletonList(role);
                cfg.securityConfig.users = Collections.singletonList(user);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            final NexusAPI api = nexusServer.getAPI("jdoe", "jdoe123");
            step("Testing 'GET /casc/config' ...", () -> {
                final ResponseBody respBody = TestUtils.call(api.getConfiguration(true));
                assertNotNull(respBody);
                final String text = respBody.string();
                assertNotNull(text);
                final Config cfg = yaml.load(text);
                assertNotNull(cfg);
            });
            step("Testing 'PUT /casc/config' ...", () -> {
                final RequestBody reqBody = RequestBody.create(TestUtils.YAML_TYPE, yaml.dump(new Config(ALWAYS)));
                final Response<ResponseBody> response = api.applyConfiguration(reqBody).execute();
                final ResponseBody respBody = response.isSuccessful() ? response.body() : response.errorBody();
                assertNotNull(respBody);
                final String result = respBody.string();
                assertTrue(response.isSuccessful(), "response from server:\n\n" + result);
                assertEquals("modified", result, "Unexpected completion code of the CASC operation");
            });
        });
    }


    private boolean applyNewConfiguration(final Config cfg) throws Exception {
        final String yamlText = yaml.dump(cfg);
        final RequestBody reqBody = RequestBody.create(TestUtils.YAML_TYPE, yamlText);
        final Response<ResponseBody> response = api.applyConfiguration(reqBody).execute();
        final ResponseBody respBody = response.isSuccessful() ? response.body() : response.errorBody();
        assertNotNull(respBody);
        final String result = respBody.string();
        assertTrue(response.isSuccessful(), "response from server:\n\n" + result);
        assertNotNull(result);
        switch (result) {
            case "modified":
                return true;
            case "not modified":
                return false;
            default:
                return Assertions.fail("Unexpected response from the server: '" + result + "'");
        }
    }

    private Config getCurrentConfiguration() throws Exception {
        return getCurrentConfiguration(false);
    }

    private Config getCurrentConfiguration(final boolean showReadOnlyObjects) throws Exception {
        final ResponseBody respBody = TestUtils.call(api.getConfiguration(showReadOnlyObjects));
        assertNotNull(respBody);
        final String text = respBody.string();
        assertNotNull(text);
        final Config cfg = yaml.load(text);
        assertNotNull(cfg);
        return cfg;
    }
}

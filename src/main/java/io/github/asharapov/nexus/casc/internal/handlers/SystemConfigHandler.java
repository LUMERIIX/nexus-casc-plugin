package io.github.asharapov.nexus.casc.internal.handlers;

import com.sonatype.nexus.clm.ClmAuthenticationType;
import com.sonatype.nexus.clm.ClmConfiguration;
import com.sonatype.nexus.clm.ClmConnector;
import com.sonatype.nexus.licensing.ext.LicenseManager;
import com.sonatype.nexus.licensing.ext.LicenseSource;
import io.github.asharapov.nexus.casc.internal.Utils;
import io.github.asharapov.nexus.casc.internal.model.SystemConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.goodies.common.Time;
import org.sonatype.nexus.CoreApi;
import org.sonatype.nexus.capability.CapabilityDescriptor;
import org.sonatype.nexus.capability.CapabilityDescriptorRegistry;
import org.sonatype.nexus.capability.CapabilityIdentity;
import org.sonatype.nexus.capability.CapabilityReference;
import org.sonatype.nexus.capability.CapabilityRegistry;
import org.sonatype.nexus.capability.CapabilityType;
import org.sonatype.nexus.crypto.secrets.Secret;
import org.sonatype.nexus.email.EmailConfiguration;
import org.sonatype.nexus.email.EmailManager;
import org.sonatype.nexus.formfields.FormField;
import org.sonatype.nexus.httpclient.HttpClientManager;
import org.sonatype.nexus.httpclient.config.AuthenticationConfiguration;
import org.sonatype.nexus.httpclient.config.ConnectionConfiguration;
import org.sonatype.nexus.httpclient.config.HttpClientConfiguration;
import org.sonatype.nexus.httpclient.config.NtlmAuthenticationConfiguration;
import org.sonatype.nexus.httpclient.config.ProxyConfiguration;
import org.sonatype.nexus.httpclient.config.ProxyServerConfiguration;
import org.sonatype.nexus.httpclient.config.UsernameAuthenticationConfiguration;
import org.sonatype.nexus.scheduling.TaskConfiguration;
import org.sonatype.nexus.scheduling.TaskDescriptor;
import org.sonatype.nexus.scheduling.TaskFactory;
import org.sonatype.nexus.scheduling.TaskInfo;
import org.sonatype.nexus.scheduling.TaskNotificationCondition;
import org.sonatype.nexus.scheduling.TaskScheduler;
import org.sonatype.nexus.scheduling.schedule.Cron;
import org.sonatype.nexus.scheduling.schedule.Daily;
import org.sonatype.nexus.scheduling.schedule.Hourly;
import org.sonatype.nexus.scheduling.schedule.Manual;
import org.sonatype.nexus.scheduling.schedule.Monthly;
import org.sonatype.nexus.scheduling.schedule.Now;
import org.sonatype.nexus.scheduling.schedule.Once;
import org.sonatype.nexus.scheduling.schedule.Schedule;
import org.sonatype.nexus.scheduling.schedule.ScheduleFactory;
import org.sonatype.nexus.scheduling.schedule.Weekly;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * @author Anton Sharapov
 */
@Named
@Singleton
public class SystemConfigHandler {

    private enum ProxyType {HTTP, HTTPS}

    private static final Logger log = LoggerFactory.getLogger(SystemConfigHandler.class);

    private final CapabilityRegistry capabilityRegistry;
    private final CapabilityDescriptorRegistry capabilityDescriptorRegistry;
    private final HttpClientManager httpClientManager;
    private final CoreApi coreApi;
    private final EmailManager emailManager;
    private final ClmConnector clmConnector;
    private final TaskScheduler taskScheduler;
    private final LicenseManager licenseManager;

    @Inject
    SystemConfigHandler(
            final CoreApi coreApi,
            final CapabilityRegistry capabilityRegistry,
            final CapabilityDescriptorRegistry capabilityDescriptorRegistry,
            final HttpClientManager httpClientManager,
            final EmailManager emailManager,
            final ClmConnector clmConnector,
            final TaskScheduler taskScheduler,
            final LicenseManager licenseManager) {
        this.coreApi = coreApi;
        this.capabilityRegistry = capabilityRegistry;
        this.capabilityDescriptorRegistry = capabilityDescriptorRegistry;
        this.httpClientManager = httpClientManager;
        this.emailManager = emailManager;
        this.clmConnector = clmConnector;
        this.taskScheduler = taskScheduler;
        this.licenseManager = licenseManager;
    }

    private static void wipe(char[] cs) {
        if (cs != null) {
            Arrays.fill(cs, '\0');
        }
    }

    private String reveal(final Object secret) {
        if (secret == null) {
            return null;
        }
        if (secret instanceof Secret) {
            char[] decrypted = null;
            try {
                decrypted = ((Secret) secret).decrypt();
                return new String(decrypted);
            }
            catch (Exception e) {
                throw new RuntimeException("Failed to decrypt secret", e);
            }
            finally {
                wipe(decrypted);
            }
        }
        return secret.toString();
    }

    public SystemConfig load(Options opts) {
        final SystemConfig config = new SystemConfig();
        config.baseUrl = getBaseUrl();
        config.connTimeout = getConnTimeout();
        config.connRetries = getConnRetries();
        config.userAgentFragment = getUserAgentFragment();
        config.httpProxy = getProxy(ProxyType.HTTP);
        config.httpsProxy = getProxy(ProxyType.HTTPS);
        config.nonProxyHosts = getNonProxyHosts();
        config.smtp = getSmtp();
        config.iq = getIq();
        config.tasks = getTasks(opts);
        config.pruneOtherExposedTasks = null;
        config.capabilities = getCapabilities();
        config.license = getLicense();
        return config;
    }

    public void store(final SystemConfig config) {
        if (config == null) {
            return;
        }
        setBaseUrl(config.baseUrl);
        setConnTimeout(config.connTimeout);
        setConnRetries(config.connRetries);
        setUserAgentFragment(config.userAgentFragment);
        setProxy(ProxyType.HTTP, config.httpProxy);
        setProxy(ProxyType.HTTPS, config.httpsProxy);
        setNonProxyHosts(config.nonProxyHosts);
        setSmtp(config.smtp);
        setIq(config.iq);
        updateTasks(config.tasks);
        pruneOtherTasks(config.pruneOtherExposedTasks, config.tasks);
        updateCapabilities(config.capabilities);
        updateLicense(config.license);
    }


    private String getBaseUrl() {
        final CapabilityType type = CapabilityType.capabilityType("baseurl");  // see also: org.sonatype.nexus.internal.app.BaseUrlCapabilityDescriptor.TYPE
        return capabilityRegistry.getAll().stream()
                .filter(cap -> type.equals(cap.context().descriptor().type()))
                .map(cap -> cap.context().properties().get("url"))
                .findFirst()
                .orElse(null);
    }

    private void setBaseUrl(String baseUrl) {
        if (baseUrl != null) {
            baseUrl = baseUrl.trim();
            if (!baseUrl.isEmpty()) {
                log.info("Setting baseUrl to {}", baseUrl);
                coreApi.baseUrl(baseUrl);
            } else {
                log.info("Remove any existing base url capabilities");
                coreApi.removeBaseUrl();
            }
        }
    }

    private Integer getConnTimeout() {
        final HttpClientConfiguration cfg = httpClientManager.getConfiguration();
        if (cfg == null) {
            return null;
        }
        final ConnectionConfiguration connCfg = cfg.getConnection();
        if (connCfg == null) {
            return null;
        }
        final Time time = connCfg.getTimeout();
        return time != null ? time.toSecondsI() : null;
    }

    private void setConnTimeout(final Integer timeout) {
        if (timeout != null) {
            coreApi.connectionTimeout(timeout);
        }
    }

    private Integer getConnRetries() {
        final HttpClientConfiguration cfg = httpClientManager.getConfiguration();
        if (cfg == null) {
            return null;
        }
        final ConnectionConfiguration connCfg = cfg.getConnection();
        return connCfg != null ? connCfg.getRetries() : null;
    }

    private void setConnRetries(final Integer retries) {
        if (retries != null) {
            coreApi.connectionRetryAttempts(retries);
        }
    }

    private String getUserAgentFragment() {
        final HttpClientConfiguration cfg = httpClientManager.getConfiguration();
        final ConnectionConfiguration connCfg = cfg.getConnection();
        return connCfg != null ? connCfg.getUserAgentSuffix() : null;
    }

    private void setUserAgentFragment(String userAgentFragment) {
        if (userAgentFragment != null) {
            coreApi.userAgentCustomization(userAgentFragment.trim());
        }
    }

    private SystemConfig.Proxy getProxy(final ProxyType proxyType) {
        final HttpClientConfiguration cfg = httpClientManager.getConfiguration();
        if (cfg == null) {
            return null;
        }
        final ProxyConfiguration pcfg = cfg.getProxy();
        if (pcfg == null) {
            return null;
        }
        final ProxyServerConfiguration pscfg;
        switch (proxyType) {
            case HTTP:
                pscfg = pcfg.getHttp();
                break;
            case HTTPS:
                pscfg = pcfg.getHttps();
                break;
            default:
                pscfg = null;
        }
        if (pscfg == null) {
            return null;
        }
        final SystemConfig.Proxy model = new SystemConfig.Proxy();
        model.host = pscfg.getHost();
        model.port = pscfg.getPort();
        model.enabled = pscfg.isEnabled();
        final AuthenticationConfiguration authcfg = pscfg.getAuthentication();
        if (authcfg instanceof UsernameAuthenticationConfiguration) {
            final UsernameAuthenticationConfiguration unauthcfg = (UsernameAuthenticationConfiguration) authcfg;
            model.auth = new SystemConfig.ProxyAuthentication();
            model.auth.user = unauthcfg.getUsername();
            model.auth.password = reveal(unauthcfg.getPassword());
        } else if (authcfg instanceof NtlmAuthenticationConfiguration) {
            final NtlmAuthenticationConfiguration ntauthcfg = (NtlmAuthenticationConfiguration) authcfg;
            model.auth = new SystemConfig.ProxyAuthentication();
            model.auth.user = ntauthcfg.getUsername();
            model.auth.password = reveal(ntauthcfg.getPassword());
            model.auth.ntlmDomain = ntauthcfg.getDomain();
            model.auth.ntlmHost = ntauthcfg.getHost();
        }
        return model;
    }

    private void setProxy(final ProxyType proxyType, SystemConfig.Proxy proxy) {
        if (proxy == null) {
            return;
        }
        switch (proxyType) {
            case HTTP:
                if (proxy.enabled) {
                    if (proxy.auth != null && proxy.auth.user != null) {
                        if (proxy.auth.ntlmHost != null || proxy.auth.ntlmDomain != null) {
                            log.info("Setting http proxy with ntlm auth (domain:{}, host:{}) to {}:{}@{}:{}",
                                    proxy.auth.ntlmDomain, proxy.auth.ntlmHost, proxy.auth.user, "******",
                                    proxy.host, proxy.port);
                            coreApi.httpProxyWithNTLMAuth(proxy.host, proxy.port,
                                    proxy.auth.user, proxy.auth.password, proxy.auth.ntlmHost, proxy.auth.ntlmDomain);
                        } else {
                            log.info("Setting http proxy with basic auth to {}:{}@{}:{}", proxy.auth.user, "******",
                                    proxy.host, proxy.port);
                            coreApi.httpProxyWithBasicAuth(proxy.host, proxy.port, proxy.auth.user, proxy.auth.password);
                        }
                    } else {
                        log.info("Setting http proxy to {}:{}", proxy.host, proxy.port);
                        coreApi.httpProxy(proxy.host, proxy.port);
                    }
                } else {
                    log.info("Removing any existing http proxy");
                    coreApi.removeHTTPProxy();
                }
                break;
            case HTTPS:
                if (proxy.enabled) {
                    if (proxy.auth != null && proxy.auth.user != null) {
                        if (proxy.auth.ntlmHost != null || proxy.auth.ntlmDomain != null) {
                            log.info("Setting https proxy with ntlm auth (domain:{}, host:{}) to {}:{}@{}:{}",
                                    proxy.auth.ntlmDomain, proxy.auth.ntlmHost, proxy.auth.user, "******",
                                    proxy.host, proxy.port);
                            coreApi.httpsProxyWithNTLMAuth(proxy.host, proxy.port,
                                    proxy.auth.user, proxy.auth.password, proxy.auth.ntlmHost, proxy.auth.ntlmDomain);
                        } else {
                            log.info("Setting https proxy with basic auth to {}:{}@{}:{}", proxy.auth.user, "******",
                                    proxy.host, proxy.port);
                            coreApi.httpsProxyWithBasicAuth(proxy.host, proxy.port, proxy.auth.user, proxy.auth.password);
                        }
                    } else {
                        log.info("Setting https proxy to {}:{}", proxy.host, proxy.port);
                        coreApi.httpsProxy(proxy.host, proxy.port);
                    }
                } else {
                    log.info("Removing any existing https proxy");
                    coreApi.removeHTTPSProxy();
                }
                break;
        }
    }

    private List<String> getNonProxyHosts() {
        final HttpClientConfiguration cfg = httpClientManager.getConfiguration();
        if (cfg == null) {
            return null;
        }
        final ProxyConfiguration pcfg = cfg.getProxy();
        if (pcfg == null) {
            return null;
        }
        final String[] hosts = pcfg.getNonProxyHosts();
        return hosts != null ? Arrays.asList(hosts) : null;
    }

    private void setNonProxyHosts(final List<String> nonProxyHosts) {
        if (nonProxyHosts == null) {
            return;
        }
        final String[] arr = nonProxyHosts.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(host -> !host.isEmpty())
                .toArray(String[]::new);
        log.info("Setting nonProxyHosts to {}", String.join(",", arr));
        coreApi.nonProxyHosts(arr);
    }


    private SystemConfig.SmtpServer getSmtp() {
        final SystemConfig.SmtpServer model = new SystemConfig.SmtpServer();
        final EmailConfiguration cfg = emailManager.getConfiguration();
        if (cfg == null) {
            model.enabled = false;
            return model;
        }
        model.enabled = cfg.isEnabled();
        model.host = cfg.getHost();
        model.port = cfg.getPort();
        model.userName = cfg.getUsername();
        model.password = reveal(cfg.getPassword());
        model.fromAddress = cfg.getFromAddress();
        model.subjectPrefix = cfg.getSubjectPrefix();
        model.startTlsEnabled = cfg.isStartTlsEnabled();
        model.startTlsRequired = cfg.isStartTlsRequired();
        model.sslOnConnectEnabled = cfg.isSslOnConnectEnabled();
        model.sslCheckServerIdentityEnabled = cfg.isSslCheckServerIdentityEnabled();
        model.nexusTrustStoreEnabled = cfg.isNexusTrustStoreEnabled();
        return model;
    }

    private void setSmtp(final SystemConfig.SmtpServer model) {
        if (model == null) {
            return;
        }
        final EmailConfiguration newCfg = emailManager.getConfiguration().copy();
        boolean changed = false;
        String passwordToSet = null;
        if (model.enabled != null && model.enabled != newCfg.isEnabled()) {
            newCfg.setEnabled(model.enabled);
            changed = true;
        }
        if (model.host != null && !model.host.equals(newCfg.getHost())) {
            newCfg.setHost(model.host);
            changed = true;
        }
        if (model.port != null && model.port != newCfg.getPort()) {
            newCfg.setPort(model.port);
            changed = true;
        }
        if (model.userName != null && !model.userName.equals(newCfg.getUsername())) {
            newCfg.setUsername(model.userName);
            changed = true;
        }
        if (model.password != null) {
            final String trimmed = model.password.trim();
            if (trimmed.isEmpty()) {
                throw new IllegalArgumentException("smtp.password is empty/whitespace");
            }
            final String currentPassword = reveal(newCfg.getPassword());
            if (!Objects.equals(trimmed, currentPassword)) {
                passwordToSet = trimmed;
                changed = true;
            }
        }
        if (model.fromAddress != null && !model.fromAddress.equals(newCfg.getFromAddress())) {
            newCfg.setFromAddress(model.fromAddress);
            changed = true;
        }
        if (model.subjectPrefix != null && !model.subjectPrefix.equals(newCfg.getSubjectPrefix())) {
            newCfg.setSubjectPrefix(model.subjectPrefix);
            changed = true;
        }
        if (model.startTlsEnabled != null && model.startTlsEnabled != newCfg.isStartTlsEnabled()) {
            newCfg.setStartTlsEnabled(model.startTlsEnabled);
            changed = true;
        }
        if (model.startTlsRequired != null && model.startTlsRequired != newCfg.isStartTlsRequired()) {
            newCfg.setStartTlsRequired(model.startTlsRequired);
            changed = true;
        }
        if (model.sslOnConnectEnabled != null && model.sslOnConnectEnabled != newCfg.isSslOnConnectEnabled()) {
            newCfg.setSslOnConnectEnabled(model.sslOnConnectEnabled);
            changed = true;
        }
        if (model.sslCheckServerIdentityEnabled != null && model.sslCheckServerIdentityEnabled != newCfg.isSslCheckServerIdentityEnabled()) {
            newCfg.setSslCheckServerIdentityEnabled(model.sslCheckServerIdentityEnabled);
            changed = true;
        }
        if (model.nexusTrustStoreEnabled != null && model.nexusTrustStoreEnabled != newCfg.isNexusTrustStoreEnabled()) {
            newCfg.setNexusTrustStoreEnabled(model.nexusTrustStoreEnabled);
            changed = true;
        }
        if (changed || passwordToSet != null) {
            log.info("Updating smtp settings ...");
            emailManager.setConfiguration(newCfg, passwordToSet);
        }
    }


    private SystemConfig.IqServer getIq() {
        final SystemConfig.IqServer model = new SystemConfig.IqServer();
        model.enabled = clmConnector.isActive();
        final ClmConfiguration cfg = clmConnector.getConfiguration();
        if (cfg != null) {
            model.url = cfg.getUrl();
            model.username = cfg.getUsername();
            model.password = cfg.getPassword();
            model.authType = cfg.getAuthenticationType() != null
                    ? SystemConfig.IqAuthType.valueOf(cfg.getAuthenticationType().name())
                    : null;
            model.attrs = new TreeMap<>();
            if (cfg.getProperties() != null) {
                for (Map.Entry<?, ?> entry : cfg.getProperties().entrySet()) {
                    final Object v = entry.getValue();
                    model.attrs.put(String.valueOf(entry.getKey()), v != null ? String.valueOf(v) : null);
                }
            }
            model.useTrustStore = cfg.getUseTrustStore();
            model.showLink = cfg.getShowLink();
            model.timeout = cfg.getTimeout();
        }
        return model;
    }

    private void setIq(final SystemConfig.IqServer model) {
        if (model == null) {
            return;
        }
        final ClmConfiguration cfg = clmConnector.getConfiguration();
        final ClmConfiguration newCfg = new ClmConfiguration();
        if (cfg != null) {
            newCfg.withUrl(cfg.getUrl())
                    .withUsername(cfg.getUsername())
                    .withPassword(cfg.getPassword())
                    .withAuthenticationType(cfg.getAuthenticationType())
                    .withProperties(cfg.getProperties())
                    .withShowLink(cfg.getShowLink())
                    .withUseTrustStore(cfg.getUseTrustStore())
                    .withTimeout(cfg.getTimeout());
        }
        boolean changed = false;
        if (model.url != null && !model.url.equals(newCfg.getUrl())) {
            newCfg.withUrl(model.url);
            changed = true;
        }
        if (model.username != null && !model.username.equals(newCfg.getUsername())) {
            newCfg.withUsername(model.username);
            changed = true;
        }
        if (model.password != null && !model.password.equals(newCfg.getPassword())) {
            newCfg.withPassword(model.password);
            changed = true;
        }
        if (model.authType != null && ClmAuthenticationType.valueOf(model.authType.name()) != newCfg.getAuthenticationType()) {
            newCfg.withAuthenticationType(ClmAuthenticationType.valueOf(model.authType.name()));
            changed = true;
        }
        if (model.attrs != null) {
            final Properties props = new Properties();
            for (Map.Entry<String, String> entry : model.attrs.entrySet()) {
                props.setProperty(entry.getKey(), entry.getValue());
            }
            if (!props.equals(newCfg.getProperties())) {
                newCfg.withProperties(props);
                changed = true;
            }
        }
        if (model.showLink != null && model.showLink != newCfg.getShowLink()) {
            newCfg.withShowLink(model.showLink);
            changed = true;
        }
        if (model.useTrustStore != null && model.useTrustStore != newCfg.getUseTrustStore()) {
            newCfg.withUseTrustStore(model.useTrustStore);
            changed = true;
        }
        if (model.timeout != null && !Objects.equals(model.timeout, newCfg.getTimeout())) {
            newCfg.withTimeout(model.timeout);
            changed = true;
        }
        boolean enabled = clmConnector.isEnabled();
        if (model.enabled != null && model.enabled != enabled) {
            enabled = model.enabled;
            changed = true;
        }
        if (changed) {
            log.info("Updating IQ server settings ...");
            clmConnector.configure(newCfg, enabled);
        }
    }


    private List<SystemConfig.Task> getTasks(final Options opts) {
        final List<SystemConfig.Task> result = new ArrayList<>();
        final List<TaskInfo> nexusTasks = taskScheduler.listsTasks();
        for (TaskInfo nt : nexusTasks) {
            final TaskConfiguration ntc = nt.getConfiguration();
            if (!ntc.isExposed() && !opts.showHiddenTasks) {
                continue;
            }
            final SystemConfig.Task model = new SystemConfig.Task();
            model.type = nt.getTypeId();
            model.name = nt.getName();
            model.message = nt.getMessage();
            model.enabled = ntc.isEnabled();
            model.visible = ntc.isVisible();
            model.exposed = ntc.isExposed();
            model.recoverable = ntc.isRecoverable();
            model.alertEmail = ntc.getAlertEmail();
            model.alertCondition = ntc.getNotificationCondition() != null
                    ? SystemConfig.TaskAlertCondition.valueOf(ntc.getNotificationCondition().name())
                    : null;
            model.attrs = new TreeMap<>();
            for (Map.Entry<String, String> entry : ntc.asMap().entrySet()) {
                if (!entry.getKey().startsWith(".") && !entry.getKey().startsWith("lastRunState.")) {  // skip common properties
                    model.attrs.put(entry.getKey(), entry.getValue());
                }
            }
            model.schedule = encodeSchedule(nt.getSchedule());
            result.add(model);
        }
        return result;
    }

    private void updateTasks(final List<SystemConfig.Task> tasks) {
        if (tasks == null) {
            return;
        }
        final TaskFactory taskFactory = taskScheduler.getTaskFactory();
        for (SystemConfig.Task model : tasks) {
            if (model == null)
                continue;
            final TaskDescriptor taskDescriptor;
            if (model.type == null || (taskDescriptor = taskFactory.findDescriptor(model.type)) == null) {
                log.error("Invalid task {}: unknown type", model);
                throw new RuntimeException("Unknown task type: " + model);
            }
            if (model.name == null) {
                log.error("Invalid task {}: name not specified", model);
                throw new RuntimeException("Unknown task name: " + model);
            }
            final TaskInfo task = taskScheduler.listsTasks().stream()
                    .filter(t -> model.type.equals(t.getTypeId()))
                    .filter(t -> model.name.equals(t.getName()))
                    .findFirst()
                    .orElse(null);

            if (task != null) { // update existed task
                applyConfiguration(taskDescriptor, task.getConfiguration(), model);
                Schedule schedule = decodeSchedule(model.schedule);
                if (schedule == null) {
                    schedule = task.getSchedule();
                }
                log.info("Updating existing task {type:{}, name:{}} ...", task.getTypeId(), task.getName());
                taskScheduler.scheduleTask(task.getConfiguration(), schedule);
            } else { // create new task
                final TaskConfiguration cfg = taskScheduler.createTaskConfigurationInstance(model.type);
                cfg.setName(model.name);
                applyConfiguration(taskDescriptor, cfg, model);
                Schedule schedule = decodeSchedule(model.schedule);
                if (schedule == null) {
                    schedule = taskScheduler.getScheduleFactory().manual();
                }
                log.info("Scheduling new task {type:{}, name:{}} ...", cfg.getTypeId(), cfg.getName());
                taskScheduler.scheduleTask(cfg, schedule);
            }
        }
    }

    private void applyConfiguration(final TaskDescriptor taskDescriptor, final TaskConfiguration cfg, final SystemConfig.Task model) {
        if (model.enabled != null) {
            cfg.setEnabled(model.enabled);
        }
        if (model.visible != null) {
            cfg.setVisible(model.visible);
        }
        if (model.recoverable != null) {
            cfg.setRecoverable(model.recoverable);
        }
        if (model.message != null) {
            cfg.setMessage(model.message);
        }
        if (model.alertEmail != null) {
            cfg.setAlertEmail(model.alertEmail);
        }
        if (model.alertCondition != null) {
            cfg.setNotificationCondition(TaskNotificationCondition.valueOf(model.alertCondition.name()));
        }
        for (FormField<?> field : taskDescriptor.getFormFields()) {
            final String id = field.getId();
            if (!field.isDisabled() && !field.isReadOnly()) {
                final Object value = field.getInitialValue();
                if (value != null) {
                    cfg.setString(id, String.valueOf(value));
                }
            }
        }
        if (model.attrs != null) {
            for (Map.Entry<String, String> entry : model.attrs.entrySet()) {
                cfg.setString(entry.getKey(), entry.getValue());
            }
        }
    }

    private SystemConfig.TaskSchedule encodeSchedule(final Schedule schedule) {
        final SystemConfig.TaskSchedule model = new SystemConfig.TaskSchedule();
        if (schedule instanceof Cron) {
            final Cron cron = (Cron) schedule;
            model.type = SystemConfig.ScheduleType.cron;
            model.startAt = cron.getStartAt();
            model.timeZone = cron.getTimeZone();
            model.cronExpr = cron.getCronExpression();
        } else if (schedule instanceof Monthly) {
            final Monthly monthly = (Monthly) schedule;
            model.type = SystemConfig.ScheduleType.monthly;
            model.startAt = monthly.getStartAt();
            model.monthDaysToRun = monthly.getDaysToRun().stream()
                    .map(Monthly.CalendarDay::getDay)
                    .collect(Collectors.toList());
        } else if (schedule instanceof Weekly) {
            final Weekly weekly = (Weekly) schedule;
            model.type = SystemConfig.ScheduleType.weekly;
            model.startAt = weekly.getStartAt();
            model.weekDaysToRun = weekly.getDaysToRun().stream()
                    .map(wd -> SystemConfig.Weekday.valueOf(wd.name()))
                    .collect(Collectors.toList());
        } else if (schedule instanceof Daily) {
            final Daily daily = (Daily) schedule;
            model.type = SystemConfig.ScheduleType.daily;
            model.startAt = daily.getStartAt();
        } else if (schedule instanceof Hourly) {
            final Hourly hourly = (Hourly) schedule;
            model.type = SystemConfig.ScheduleType.hourly;
            model.startAt = hourly.getStartAt();
        } else if (schedule instanceof Once) {
            final Once once = (Once) schedule;
            model.type = SystemConfig.ScheduleType.once;
            model.startAt = once.getStartAt();
        } else if (schedule instanceof Now) {
            model.type = SystemConfig.ScheduleType.now;
        } else if (schedule instanceof Manual) {
            model.type = SystemConfig.ScheduleType.manual;
        } else {
            log.error("Can't resolve nexus scheduler '{}'", schedule);
            return null;
        }
        return model;
    }

    private Schedule decodeSchedule(final SystemConfig.TaskSchedule model) {
        if (model == null) {
            return null;
        }
        if (model.type == null) {
            log.warn("Schedule type must be specified");
            return null;
        }
        final ScheduleFactory scheduleFactory = taskScheduler.getScheduleFactory();
        final Date startAt = model.startAt != null ? model.startAt : new Date();
        switch (model.type) {
            case cron:
                if (model.cronExpr == null) {
                    log.warn("Cron expression should be specified for '{}' task", model.type);
                    return null;
                }
                return model.timeZone != null
                        ? scheduleFactory.cron(startAt, model.cronExpr, model.timeZone.getID())
                        : scheduleFactory.cron(startAt, model.cronExpr);
            case monthly:
                if (model.monthDaysToRun == null || model.monthDaysToRun.isEmpty()) {
                    log.warn("monthDaysToRun should be specified for '{}' task", model.type);
                    return null;
                }
                final Set<Monthly.CalendarDay> monthDays = model.monthDaysToRun.stream()
                        .filter(Objects::nonNull)
                        .map(Monthly.CalendarDay::day)
                        .collect(Collectors.toSet());
                return scheduleFactory.monthly(startAt, monthDays);
            case weekly:
                if (model.weekDaysToRun == null || model.weekDaysToRun.isEmpty()) {
                    log.error("weekDaysToRun should be specified for '{}' task", model.type);
                    return null;
                }
                final Set<Weekly.Weekday> weekdays = model.weekDaysToRun.stream()
                        .filter(Objects::nonNull)
                        .map(day -> Weekly.Weekday.valueOf(day.toString()))
                        .collect(Collectors.toSet());
                return scheduleFactory.weekly(startAt, weekdays);
            case daily:
                return scheduleFactory.daily(startAt);
            case hourly:
                return scheduleFactory.hourly(startAt);
            case once:
                return scheduleFactory.once(startAt);
            case now:
                return scheduleFactory.now();
            case manual:
            default:
                return scheduleFactory.manual();
        }
    }

    private void pruneOtherTasks(final Boolean pruneTasks, final List<SystemConfig.Task> allowedTasks) {
        if (pruneTasks == null || !pruneTasks) {
            return;
        }
        final Set<String> allowedKeys = allowedTasks != null
                ? allowedTasks.stream().map(t -> t.type + "." + t.name).collect(Collectors.toSet())
                : Collections.emptySet();

        for (TaskInfo task : taskScheduler.listsTasks()) {
            if (!task.getConfiguration().isExposed()) {
                continue;
            }
            if (allowedKeys.contains(task.getTypeId() + "." + task.getName())) {
                continue;
            }
            log.info("Removing task {type:{}, name:{}} ...", task.getTypeId(), task.getName());
            final boolean ok = task.remove();
            if (!ok) {
                log.warn("Task {type:{}, name:{}} can't be removed", task.getTypeId(), task.getName());
            }
        }
    }


    private List<SystemConfig.Capability> getCapabilities() {
        final List<SystemConfig.Capability> result = new ArrayList<>();
        for (CapabilityReference cap : capabilityRegistry.getAll()) {
            final SystemConfig.Capability model = new SystemConfig.Capability();
            model.type = cap.context().type().toString();
            model.enabled = cap.context().isEnabled();
            model.notes = cap.context().notes();
            model.attrs = cap.context().properties();
            result.add(model);
        }
        return result;
    }

    private CapabilityIdentity getCapabilityId(CapabilityReference existing) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Method m = existing.getClass().getMethod("id");
        return (CapabilityIdentity) m.invoke(existing);
    }

    private void updateCapabilities(final List<SystemConfig.Capability> capabilities) {
        if (capabilities == null) {
            return;
        }
        for (SystemConfig.Capability model : capabilities) {
            final CapabilityType type = CapabilityType.capabilityType(model.type);
            final CapabilityDescriptor descriptor = capabilityDescriptorRegistry.get(type);
            if (descriptor == null) {
                throw new RuntimeException("Unsupported capability '" + type + "'");
            }
            if (model.attrs == null) {
                model.attrs = new HashMap<>();
            }
            for (FormField<?> field : descriptor.formFields()) {
                final String id = field.getId();
                if (!field.isDisabled() && !field.isReadOnly() && !model.attrs.containsKey(id)) {
                    final Object value = field.getInitialValue();
                    if (value != null) {
                        model.attrs.put(id, String.valueOf(value));
                    }
                }
            }

            final CapabilityReference existing = capabilityRegistry.getAll().stream()
                    .filter(cap -> cap.context().type().equals(type))
                    .findFirst()
                    .orElse(null);

            if (existing != null) {
                try {
                    final CapabilityIdentity id = getCapabilityId(existing);
                    log.info("Updating capability of type {} and id {}", model.type, id);
                    final boolean enabled = model.enabled == null ? existing.context().isEnabled() : model.enabled;
                    capabilityRegistry.update(
                            id,
                            enabled,
                            model.notes,
                            model.attrs
                    );
                } catch (Exception e) {
                    log.error("Can't update capability of type '" + model.type + " : " + e.getMessage(), e);
                    throw new RuntimeException(e.getMessage(), e);
                }
            } else {
                try {
                    log.info("Creating capability of type {}", model.type);
                    final boolean enabled = model.enabled == null || model.enabled;
                    capabilityRegistry.add(
                            type,
                            enabled,
                            model.notes,
                            model.attrs
                    );
                } catch (Exception e) {
                    log.error("Can't add capability of type '" + model.type + " : " + e.getMessage(), e);
                    throw new RuntimeException(e.getMessage(), e);
                }
            }
        }
    }


    private SystemConfig.License getLicense() {
        return new SystemConfig.License();
    }

    private void updateLicense(final SystemConfig.License model) {
        if (model == null) {
            return;
        }
        if (model.installFrom != null) {
            log.info("Installing Sonatype Nexus Pro license from source '{}' ...", model.installFrom);
            final byte[] licenseData;
            try {
                licenseData = Utils.load(model.installFrom);
            } catch (IOException e) {
                throw new RuntimeException("Can't load license from uri '" + model.installFrom + "' : " + e.getMessage(), e);
            }
            try {
                licenseManager.installLicense(licenseData, LicenseSource.API);
                log.info("Sonatype Nexus Pro license installed successfully.");
            } catch (Exception e) {
                throw new RuntimeException("Can't install license from uri '" + model.installFrom + "' : " + e.getMessage(), e);
            }
        }
    }
}

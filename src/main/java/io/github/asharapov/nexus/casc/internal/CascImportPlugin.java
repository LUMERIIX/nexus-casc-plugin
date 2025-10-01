package io.github.asharapov.nexus.casc.internal;

import io.github.asharapov.nexus.casc.internal.handlers.ConfigHandler;
import org.eclipse.sisu.Description;
import org.sonatype.nexus.common.app.ManagedLifecycle;
import org.sonatype.nexus.common.event.EventManager;
import org.sonatype.nexus.common.stateguard.StateGuardLifecycleSupport;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

@Named("cascPlugin")
@Description("Casc Plugin")
// Plugin must run after CAPABILITIES phase as otherwise we can not load/patch existing capabilities
@ManagedLifecycle(phase = ManagedLifecycle.Phase.TASKS)
@Singleton
public class CascImportPlugin extends StateGuardLifecycleSupport {

    private final ConfigHandler configHandler;
    private final EventManager eventManager;
    private final AtomicBoolean importRequested = new AtomicBoolean();

    private ScheduledExecutorService executor;
    private ScheduledFuture<?> importFuture;

    @Inject
    public CascImportPlugin(final ConfigHandler configHandler,
                            final EventManager eventManager) {
        this.configHandler = configHandler;
        this.eventManager = eventManager;
    }

    @Override
    protected void doStart() {
        String pathsstr = System.getenv(Constants.CASC_IMPORT_PATH_ENV);
        if (pathsstr == null) {
            pathsstr = System.getenv(Constants.CASC_IMPORT_PATH_LEGACY_ENV);
        }
        if (pathsstr == null) {
            pathsstr = Constants.CASC_IMPORT_PATH_DEFAULT;
        }
        final Path path = Paths.get(pathsstr);
        if (!Files.isRegularFile(path)) {
            log.warn("CASC: file '{}' not found. Nothing to import.", path);
            return;
        }

        scheduleImport(path);
    }

    @Override
    protected void doStop() throws Exception {
        cancelScheduledImport();
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
        importRequested.set(false);
        super.doStop();
    }

    private void scheduleImport(final Path path) {
        if (importRequested.get()) {
            return;
        }
        if (executor == null) {
            executor = Executors.newSingleThreadScheduledExecutor(r -> {
                final Thread thread = new Thread(r, "casc-import-runner");
                thread.setDaemon(true);
                return thread;
            });
        }

        log.info("CASC: configuration file '{}' detected, waiting for the event system to become idle before applying it", path);
        importFuture = executor.scheduleWithFixedDelay(() -> tryImport(path), 1, 1, TimeUnit.SECONDS);
    }

    private void tryImport(final Path path) {
        if (!Files.isRegularFile(path)) {
            log.warn("CASC: file '{}' disappeared before import could run.", path);
            cancelScheduledImport();
            return;
        }

        final boolean calm;
        try {
            calm = eventManager.isCalmPeriod();
        } catch (Exception e) {
            log.debug("CASC: event manager not yet ready to report calm period: {}", e.getMessage());
            return;
        }

        if (!calm) {
            log.debug("CASC: event system still busy, postponing CASC import for '{}'.", path);
            return;
        }

        if (!importRequested.compareAndSet(false, true)) {
            return;
        }

        cancelScheduledImport();
        processImport(path);
    }

    private void processImport(final Path path) {
        log.info("CASC: processing configuration file '{}' ...", path);
        try {
            final String text = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
            final boolean applied = configHandler.store(text);
            log.info("CASC: file '{}' processing completed {}.", path, (applied ? "successfully" : "without any changes"));
        } catch (Exception e) {
            log.error("CASC: file '" + path + "' processing failed with error: " + e.getMessage(), e);
        }
    }

    private void cancelScheduledImport() {
        if (importFuture != null) {
            importFuture.cancel(false);
            importFuture = null;
        }
    }
}

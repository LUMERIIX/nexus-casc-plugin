package io.github.asharapov.nexus.casc.internal;

import org.sonatype.nexus.common.app.ApplicationDirectories;
import org.sonatype.nexus.formfields.CheckboxFormField;
import org.sonatype.nexus.formfields.FormField;
import org.sonatype.nexus.formfields.StringTextFormField;
import org.sonatype.nexus.scheduling.TaskDescriptorSupport;
import org.sonatype.nexus.common.upgrade.AvailabilityVersion;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

/**
 * Descriptor for {@link CascExportTask} task.
 *
 * @author Anton Sharapov
 */
@Named
@Singleton
@AvailabilityVersion(from = "1.0")
public class CascExportTaskDescriptor extends TaskDescriptorSupport {

    public static final String TYPE_ID = "casc.export";
    public static final String TYPE_NAME = "CASC - Export configuration";

    public static final String CASC_EXPORT_PATH_FIELD = "casc.export.path";
    private static final String CASC_EXPORT_PATH_LABEL = "Path to target file";
    private static final String CASC_EXPORT_PATH_HELP_TXT =
            "Full path to target file where the Sonatype Nexus configuration will be written. " +
                    "Make sure that the Sonatype Nexus process has write permissions to this directory.";

    public static final String CASC_EXPORT_EMPTY_FIELD = "casc.export.empty-properties";
    public static final boolean CASC_EXPORT_EMPTY_DEFAULT_VALUE = true;
    private static final String CASC_EXPORT_EMPTY_LABEL = "Print empty properties";
    private static final String CASC_EXPORT_EMPTY_HELP_TEXT =
            "Allows showing properties with 'null' values. ";

    public static final String CASC_EXPORT_EMPTY_COLLECTIONS_FIELD = "casc.export.empty-collections";
    public static final boolean CASC_EXPORT_EMPTY_COLLECTIONS_DEFAULT_VALUE = true;
    private static final String CASC_EXPORT_EMPTY_COLLECTIONS_LABEL = "Print empty collections";
    private static final String CASC_EXPORT_EMPTY_COLLECTIONS_HELP_TEXT =
            "Allows showing properties that referencing to empty collections or maps. ";

    public static final String CASC_EXPORT_RO_FIELD = "casc.export.readonly-objects";
    public static final boolean CASC_EXPORT_RO_DEFAULT_VALUE = false;
    private static final String CASC_EXPORT_RO_LABEL = "Print non modifiable objects";
    private static final String CASC_EXPORT_RO_HELP_TEXT =
            "Includes information about non modifiable Sonatype Nexus objects (these may be some privileges, roles, users, tasks) " +
                    "that will be marked as 'readOnly' in the target file";

    public static final String CASC_EXPORT_HIDDEN_TASKS_FIELD = "casc.export.hidden-tasks";
    public static final boolean CASC_EXPORT_HIDDEN_TASKS_DEFAULT_VALUE = false;
    private static final String CASC_EXPORT_HIDDEN_TASKS_LABEL = "Print hidden tasks";
    private static final String CASC_EXPORT_HIDDEN_TASKS_HELP_TEXT =
            "Includes information about tasks that are not visible in the UI to any users (including administrators).";

    @Inject
    public CascExportTaskDescriptor(final ApplicationDirectories appDirectories) {
        super(TYPE_ID,
                CascExportTask.class,
                TYPE_NAME,
                VISIBLE,
                EXPOSED,
                new StringTextFormField(
                        CASC_EXPORT_PATH_FIELD,
                        CASC_EXPORT_PATH_LABEL,
                        CASC_EXPORT_PATH_HELP_TXT,
                        FormField.MANDATORY
                ).withInitialValue(Utils.getDefaultCascExportPath(appDirectories)),
                new CheckboxFormField(
                        CASC_EXPORT_EMPTY_FIELD,
                        CASC_EXPORT_EMPTY_LABEL,
                        CASC_EXPORT_EMPTY_HELP_TEXT,
                        FormField.MANDATORY
                ).withInitialValue(CASC_EXPORT_EMPTY_DEFAULT_VALUE),
                new CheckboxFormField(
                        CASC_EXPORT_EMPTY_COLLECTIONS_FIELD,
                        CASC_EXPORT_EMPTY_COLLECTIONS_LABEL,
                        CASC_EXPORT_EMPTY_COLLECTIONS_HELP_TEXT,
                        FormField.MANDATORY
                ).withInitialValue(CASC_EXPORT_EMPTY_COLLECTIONS_DEFAULT_VALUE),
                new CheckboxFormField(
                        CASC_EXPORT_RO_FIELD,
                        CASC_EXPORT_RO_LABEL,
                        CASC_EXPORT_RO_HELP_TEXT,
                        FormField.MANDATORY
                ).withInitialValue(CASC_EXPORT_RO_DEFAULT_VALUE),
                new CheckboxFormField(
                        CASC_EXPORT_HIDDEN_TASKS_FIELD,
                        CASC_EXPORT_HIDDEN_TASKS_LABEL,
                        CASC_EXPORT_HIDDEN_TASKS_HELP_TEXT,
                        FormField.MANDATORY
                ).withInitialValue(CASC_EXPORT_HIDDEN_TASKS_DEFAULT_VALUE)
        );
    }

}

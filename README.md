[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.asharapov.nexus/nexus-casc-plugin/badge.png)](https://search.maven.org/artifact/io.github.asharapov.nexus/nexus-casc-plugin/)

# Nexus Configuration as Code

Nexus CasC is a configuration as code plugin for Sonatype Nexus Repository Manager 3.

This plugin allows to specify a YAML file to configure a Nexus instance on startup.

## Why Fork?

Forked from: https://github.com/AdaptiveConsulting/nexus-casc-plugin

Many new features were added that changed the format of the config file and thus broke backward compatibility 
with previous versions of the plugin.

### Changes from the fork

* Added support for all Sonatype Repository Manager (OSS edition) settings except scripts, including:
  - improved and extended configuration of HTTP/HTTPS connections;
  - added support for configuring SMTP parameters;
  - added support for tasks scheduling configuration;
  - added support for Nexus Repository Manager (Pro edition) license installation;
  - added support for configuring Nexus IQ server integration;
  - added support for configuring LDAP server integration;
  - added support for trusted SSL certificates configuration;
  - added support for content selectors configuration;
  - added support for routing rules configuration.
* The plugin now has a REST API (available for authenticated users with administrators privileges) that can be used for: 
  - exporting the current server configuration to a YAML file;
  - importing the configuration from a YAML file to the server.
* Added support for a new type ('CASC - Export configuration') of scheduling tasks that can be used to export 
the current Nexus configuration to a YAML file.
* Improvements have been made to the process of configuring server parameters (either automatically when it starts, or using the REST API plugin).
  Now you can manage the conditions under which the settings contained in the proposed YAML configuration file will actually be applied on the server:
   - on demand (either automatically when starting the server, or when calling the corresponding method using the plugin REST API),
    regardless of whether the plugin has previously made any changes to the settings of this Nexus server instance;
   - only if one of two conditions is met:
      - either the plugin has not previously made any changes to the settings of this instance of the Nexus server;
      - or the content of the previously loaded configuration file differs from the content of the configuration file that is offered to be loaded now;
   - only if the plugin has not previously made any changes to the settings of this instance of the Nexus server.
This was implemented with an additional `metadata.executionPolicy` parameter in the YAML configuration file,
which can take one of three values: `ALWAYS`, `IF_CHANGED`, `ONLY_ONCE`.
* Integration tests now cover most of the functionality provided by the plugin.
* The groupId has changed to avoid clashing with the original project.


## Usage

**Warning**: Use the project version that matches your Nexus version.
This is because the project is tied to specific version of the Nexus API and there is no guarantee
the API remains consistent.

Deploy the .kar archive using the upstream `sonatype/nexus3` image in the `/opt/sonatype/nexus/deploy/` directory.
The plugin will be automatically installed on startup.

An example of a custom Nexus docker image with the CasC plugin installed (you may need to update the Nexus and plugin versions):
```dockerfile
FROM sonatype/nexus3:3.45.0
ARG PLUGIN_VERSION=3.45.0.1
USER root
RUN set -eux; \
    curl -L -f -o /opt/sonatype/nexus/deploy/nexus-casc-plugin-${PLUGIN_VERSION}-bundle.kar \
        https://repo1.maven.org/maven2/io/github/asharapov/nexus/nexus-casc-plugin/${PLUGIN_VERSION}/nexus-casc-plugin-${PLUGIN_VERSION}-bundle.kar;
USER nexus
``` 

The CasC plugin expects a YAML configuration file to be mounted to `/opt/nexus.yml` (this path can be overridden using the either `NEXUS_CASC_IMPORT_PATH` or `NEXUS_CASC_CONFIG` env var).  
Start Nexus as usual.

An example of a custom Nexus image with the CasC plugin and config file installed: 
```dockerfile
FROM sonatype/nexus3:3.45.0
ARG PLUGIN_VERSION=3.45.0.1
USER root
RUN set -eux; \
    curl -L -f -o /opt/sonatype/nexus/deploy/nexus-casc-plugin-${PLUGIN_VERSION}-bundle.kar \
        https://repo1.maven.org/maven2/io/github/asharapov/nexus/nexus-casc-plugin/${PLUGIN_VERSION}/nexus-casc-plugin-${PLUGIN_VERSION}-bundle.kar;
USER nexus
COPY my-nexus-config.yml /opt/nexus.yml
``` 

The simplest and recommended procedure for preparing a YAML configuration file is as follows:
1. Start a separate instance of the Nexus server with the CasC plugin installed.
2. Using standard Nexus administration tools, make all the necessary changes to its settings.
3. Export the current Nexus server settings to a file using the plugin REST API or 'CASC - Export configuration' task.
4. Use the resulting YAML file as a template to set up your Nexus target servers.  

**Known issues**:  
When exporting the current server configuration, the following parameters cannot be restored:
   - sources for downloading trusted certificates (paths/urls to PEM files, list of external hosts);
   - path (or url) to the Nexus Repository Manager (Pro edition) license file.  
The values of the above parameters should be added to the exported configuration file manually (see the corresponding fragment of the configuration file below).
```yaml
metadata:
  executionPolicy: IF_CHANGED # this configuration will only be processed if it was not imported earlier (or if any changes have been made to it since then) 
systemConfig:
# ...
  license:
    installFrom: /opt/sonatype-repository-manager-trial.lic  # the Nexus Repository Pro license will be installed from the specified file
# ...
securityConfig:
# ...
  trustedCerts:
    fromPEMFiles:
      - file:///opt/certs/www-postgresql-org-chain.pem  # the chain of the trusted certificates will be loaded from the specified URL
      - /opt/certs/www-redhat-com-chain.pem             # the chain of the trusted certificates will be loaded from the specified local file
    fromServers:
      - host: www.oracle.com                            # the chain of the trusted certificates will be obtained from the given server (port 443 used as default)
        port: 443
      - host: www.google.com
# ...
```


## CasC REST API

Examples of commands for exporting the current configuration (with the option to hide non-modifiable or system parameters - by default, or not):
```shell script
$ curl -u admin:admin123 -X GET "http://localhost:8081/service/rest/casc/config" > nexus-config.yml
$ curl -u admin:admin123 -X GET "http://localhost:8081/service/rest/casc/config?showReadOnlyObjects=true" > nexus-config.yml
```

Example of a command to import a Nexus server configuration from a file:
```shell script
$ curl -u admin:admin123 -X POST "http://localhost:8081/service/rest/casc/config" -H "Content-Type: text/vnd.yaml" --data-binary @nexus-config.yml
```


## Configuration file

You can find an example configuration file [here](./examples/nexus-demo.yml).

### Interpolation

Use `${ENV_VAR}` for env var interpolation. Use `${ENV_VAR:default}` or `${ENV_VAR:"default"}` for default values.

Use `${file:/path/to/a/file}` to include the contents of a file.


## How to build

#### Requirements
1. JDK 8+
2. Maven 3.6+
3. Docker (for integration testing and to run the examples)
4. docker-compose (to run the examples)

#### Building the plugin

To build a plugin, use the command:
```shell script
$ mvn -U clean package
```

To deploy the built version of the plugin to *maven central* use the command
```shell script
$ mvn -U clean deploy -P release.oss
```

To run all integration tests and generate a report on their execution, use the command:
```shell script
$ mvn -U clean verify allure:aggregate
```

To show the generated report, you can use the command below, but it is better to use the [allure](http://allure.qatools.ru/) plugin for your preferred CI/CD service.
```shell script
./.allure/allure-2.20.1/bin/allure open -h localhost -p 35000 target/site/allure-maven-plugin
```

##### Workaround: 3.72.0-04
The following dependencies were removed from the public Maven repository. To build the project, you need to extract them from the Nexus installation package and install them in your local Maven repository.

use the following command to install the .jar file in your local Maven repository:
```shell script
mvn install:install-file -Dfile=path-to-file.jar -DgroupId=org.sonatype.nexus -DartifactId=artifact-id -Dversion=<version> -Dpackaging=jar -DgeneratePom=true
```

**Dependencies to be installed from Nexus installation package:**
* nexus-ldap-plugin (install as `com.sonatype.nexus.plugins:nexus-ldap-plugin`)
* nexus-licensing-extension (install as `com.sonatype.nexus:nexus-licensing-extension`)
* nexus-healthcheck-base (install as `com.sonatype.nexus.plugins:nexus-healthcheck-base`)

They can be found in nexus-<version>/system/com/sonatype/nexus/plugins/* and nexus-<version>/system/com/sonatype/nexus/* directories of the Nexus installation package respectively.
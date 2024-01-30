#!/usr/bin/env bash
set -ueo pipefail;

CLEAN=0
if [ "$1" = "--clean" ]; then
    CLEAN=1
    shift;
fi

VER="${1:-3.45.0-01}"

declare -a REQUIRED_DEPS
REQUIRED_DEPS[0]="com.sonatype.nexus:nexus-licensing-extension"
REQUIRED_DEPS[1]="com.sonatype.nexus.plugins:nexus-healthcheck-base"
REQUIRED_DEPS[2]="com.sonatype.nexus.plugins:nexus-ldap-plugin"

BASE_DIR="$(cd -P "$(dirname "${0}")" && pwd)";

installFile() {
    local group="${1}";
    local artifact="${2}";
    local version="${3}";
    local dir="${4:-"${BASE_DIR}"}";
    local opts="";

    echo "installing ${group}:${artifact}:${version} ...";
    if [ -f "${dir}/${artifact}.jar" ]; then
        opts="${opts} -Dfile=${dir}/${artifact}.jar";
        if [ -f "${dir}/${artifact}.pom" ]; then
            opts="${opts} -DpomFile=${dir}/${artifact}.pom";
        fi
    else
        if [ -f "${dir}/${artifact}-${version}.jar" ]; then
            opts="${opts} -Dfile=${dir}/${artifact}-${version}.jar";
            if [ -f "${dir}/${artifact}-${version}.pom" ]; then
                opts="${opts} -DpomFile=${dir}/${artifact}-${version}.pom";
            fi
        else
            echo "WARN: No files ${dir}/${artifact}-${version}.jar or ${dir}/${artifact}.jar found. Skipped.";
            return 1;
        fi
    fi

    artifact=$(echo -n "${artifact}" | tr '[:upper:]' '[:lower:]');
    mvn -q install:install-file  -DgroupId="${group}" -DartifactId="${artifact}" -Dversion="${version}" \
                          ${opts} -Dpackaging=jar -DcreateChecksum=true;
}

if ! [ -f "nexus-oss.tar.gz" ]; then
    echo "Downloading Nexus OSS ${VER} ..."
    wget -q "https://download.sonatype.com/nexus/3/nexus-${VER}-unix.tar.gz" -O nexus-oss.tar.gz
fi

echo "Extracting Nexus OSS ${VER} ..."
tar -zxf nexus-oss.tar.gz

if [ ${CLEAN} -eq 1 ]; then
    echo "Cleaning old dependencies ..."
    rm -rf "${BASE_DIR}/com"
fi

for dep in ${REQUIRED_DEPS[*]}; do
    parts=(${dep//:/ })
    group=${parts[0]}
    artifact=${parts[1]}
    cp "nexus-${VER}/system/${group//.//}/${artifact}/${VER}/${artifact}-${VER}.jar" .
    installFile "${group}" "${artifact}" "${VER}" "."
done

echo "Cleaning ..."
rm -rf nexus-oss.tar.gz sonatype-work nexus-${VER} *.jar

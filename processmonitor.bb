DESCRIPTION = "Linux process monitor - track and record the execution times of all processes"

LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=894d9b830cb1f38db58741000f9c2c7f"

S = "${WORKDIR}/git"
SRC_URI = "https://github.com/TeknoVenus/ProcessMonitor.git;branch=main"
SRCREV = "bc028ede4e498afe11fe19e9d2607cd21b92e631"

inherit cmake systemd

do_install_append () {
    install -d ${D}${systemd_unitdir}/system
    install -m 0644 ${S}/process-monitor.service ${D}${systemd_unitdir}/system
}

SYSTEMD_SERVICE_${PN} = "process-monitor.service"

FILES_${PN} += "${systemd_system_unitdir}/process-monitor.service"
FILES_${PN} += "${bindir}/ProcessMonitor"

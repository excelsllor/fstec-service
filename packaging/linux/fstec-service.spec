# -*- spec -*-
# rpm-пакет ФСТЭК Сервис (микросервисный web-режим).
# Ставит: services/ (FastAPI микросервисы), frontend/dist, systemd-юниты
#         fstec-gateway.service + fstec-worker@{ingest,llm,security,reporting}.
# Python-зависимости устанавливаются отдельно (pip; офлайн — из wheelhouse).
#
# Сборка:
#   rpmbuild -bb fstec-service.spec --define "_sourcedir <SRC>"
# где <SRC> содержит:
#   services/                - каталог микросервисов (Python)
#   frontend/                - собранный Vite dist
#   fstec-gateway.service
#   fstec-worker@.service
#   fstec-service.desktop
#   fstec-service.png

Name:           fstec-service
Version:        0.1.0
Release:        1%{?dist}
Summary:        FSTEC Service - microservices web mode
License:        Proprietary
Group:          Applications/Productivity
BuildArch:      noarch
Requires:       python3 >= 3.10
AutoReqProv:    yes

%description
Сервис обработки писем по результатам мониторинга ИСПДн (микросервисы:
api-gateway :8666 + воркеры ingest/llm/security/reporting).
Интерфейс открывается в браузере по адресу http://127.0.0.1:8666.
Python-зависимости ставятся через pip после установки пакета.

%build

%pre
getent group fstec >/dev/null || groupadd -r fstec
getent passwd fstec >/dev/null || useradd -r -g fstec -d /var/lib/fstec-service -s /sbin/nologin -c "FSTEC Service" fstec

%install
rm -rf %{buildroot}
install -d %{buildroot}/opt/fstec-service/services
install -d %{buildroot}/opt/fstec-service/frontend
install -d -m 0700 %{buildroot}/var/lib/fstec-service
install -d %{buildroot}/usr/lib/systemd/system
install -d %{buildroot}/usr/share/applications
install -d %{buildroot}/usr/share/icons/hicolor/128x128/apps

cp -a %{_sourcedir}/services/. %{buildroot}/opt/fstec-service/services/
cp -a %{_sourcedir}/frontend/. %{buildroot}/opt/fstec-service/frontend/
install -m 0644 %{_sourcedir}/fstec-gateway.service %{buildroot}/usr/lib/systemd/system/fstec-gateway.service
install -m 0644 %{_sourcedir}/fstec-worker@.service %{buildroot}/usr/lib/systemd/system/fstec-worker@.service
install -m 0644 %{_sourcedir}/fstec-service.desktop %{buildroot}/usr/share/applications/fstec-service.desktop
install -m 0644 %{_sourcedir}/fstec-service.png %{buildroot}/usr/share/icons/hicolor/128x128/apps/fstec-service.png

%post
systemctl daemon-reload || :
systemctl enable fstec-gateway.service fstec-worker@{ingest,llm,security,reporting}.service || :

%preun
if [ "$1" = "0" ]; then
    systemctl stop fstec-gateway.service fstec-worker@{ingest,llm,security,reporting}.service || :
    systemctl disable fstec-gateway.service fstec-worker@{ingest,llm,security,reporting}.service || :
fi

%postun
systemctl daemon-reload || :

%files
%attr(0750, fstec, fstec) /opt/fstec-service/services
%attr(0755, fstec, fstec) /opt/fstec-service/frontend
%attr(0700, fstec, fstec) %dir /var/lib/fstec-service
/usr/lib/systemd/system/fstec-gateway.service
/usr/lib/systemd/system/fstec-worker@.service
/usr/share/applications/fstec-service.desktop
/usr/share/icons/hicolor/128x128/apps/fstec-service.png
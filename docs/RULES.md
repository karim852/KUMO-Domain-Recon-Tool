# Kumo vulnerability playbook

**420 rules.** Every one is a GET plus a response signature: Kumo probes a path and matches evidence in the reply. No rule sends a payload, executes anything, or interacts with what it finds.

Validation: `test_rules.py` runs every rule against 11 decoy responses, proves each rule's evidence survives its own path scrub, and checks version rules against both vulnerable and patched releases. `test_versions.py` repeats the version checks over real HTTP. `test_fp.py` scans nine benign host shapes. `test_live.py` scans the vulnerable lab.

Findings carry a `confidence` field. `confirmed` means the response itself held the evidence; `version-inference` means only an advertised version number was compared, which a backported distro patch can leave stale — verify those before reporting.

| severity | count |
|---|---|
| critical | 58 |
| high | 162 |
| medium | 137 |
| low | 63 |

**Origin:** nuclei 338, handwritten 32, kumo-webshell 27, nuclei-unauth 23

| # | severity | id | path | name |
|---|---|---|---|---|
| 1 | critical | `CVE-2024-40711` | `/api/v1/serverinfo` | Veeam Backup & Replication - Unauthenticated |
| 2 | critical | `CVE-2025-49001` | `/de2api/user/info` | DataEase < 2.10.10 - JWT Authentication Bypass |
| 3 | critical | `CVE-2026-18072` | `/?_wplogin=35fe7057ffed92ff7bc5a0b90f302a77fb5843ad6c972294d68da0b0553b3900` | Advanced Responsive Video Embedder 10.8.7/10.8.8 - Hardcoded B |
| 4 | critical | `CVE-2026-21445` | `/api/v1/monitor/messages` | Langflow - Broken Access Control |
| 5 | critical | `CVE-2026-42281` | `/cors?url=http://127.0.0.1:8080/version` | MagicMirror <= 2.35.0 - Server-Side Request Forgery |
| 6 | critical | `CVE-2026-59774` | `/api/v1/repos/search?limit=1` | Gitea 1.22.1-1.27.0 - Unauthenticated Arbitrary File Read |
| 7 | critical | `CVE-2026-67208` | `/h2-console/` | Juggle <= 1.6.0 - Unauthenticated Exposed H2 Database Console |
| 8 | critical | `aem-groovyconsole` | `/groovyconsole` | AEM Groovy Console Discovery |
| 9 | critical | `aws-credentials` | `/.aws/credentials` | AWS Credentials File Exposed |
| 10 | critical | `axiom-digitalocean-key-exposure` | `/.axiom/accounts/do.json` | DigitalOcean Key Exposure via Axiom |
| 11 | critical | `bitbucket-auth-bypass` | `/admin%20/db` | Bitbucket Server > 4.8 - Authentication Bypass |
| 12 | critical | `circarlife-installer` | `/html/setup.html` | CirCarLife - Installer |
| 13 | critical | `commax-credentials-disclosure` | `/overview.asp` | COMMAX Smart Home Ruvie CCTV Bridge DVR - RTSP Credentials Dis |
| 14 | critical | `docker-api` | `/version` | Docker Remote API Exposed |
| 15 | critical | `elasticsearch` | `/_cluster/health` | Elasticsearch Exposed |
| 16 | critical | `env-file` | `/.env` | Environment File Exposed |
| 17 | critical | `getsimple-installation` | `/admin/install.php` | GetSimple CMS - Installer |
| 18 | critical | `htpasswd` | `/.htpasswd` | .htpasswd Exposed |
| 19 | critical | `jupyter-ipython-unauth` | `/ipython/tree` | Jupyter ipython - Authorization Bypass |
| 20 | critical | `kubernetes-api` | `/api/v1/namespaces` | Kubernetes API Exposed |
| 21 | critical | `laravel-debug` | `/_ignition/health-check` | Laravel Debug Mode / Ignition |
| 22 | critical | `misconfigured-docker` | `/images/json` | Docker Container - Misconfiguration Exposure |
| 23 | critical | `npm-token` | `/.npmrc` | .npmrc Token Exposed |
| 24 | critical | `spring-actuator-env` | `/actuator/env` | Spring Actuator /env Exposed |
| 25 | critical | `spring-heapdump` | `/actuator/heapdump` | Spring Actuator Heap Dump |
| 26 | critical | `sql-dump` | `/dump.sql` | SQL Dump Exposed |
| 27 | critical | `ssh-private-key` | `/id_rsa` | SSH Private Key Exposed |
| 28 | critical | `tugboat-config-exposure` | `/.tugboat` | Tugboat Configuration File Exposure |
| 29 | critical | `webshell-404-decoy` | `/404.php` | Backdoor disguised as 404 handler |
| 30 | critical | `webshell-alfa` | `/alfa.php` | ALFA TEaM Web Shell Present |
| 31 | critical | `webshell-alfa-data` | `/wp-includes/ALFA_DATA/` | ALFA Shell Data Directory Present |
| 32 | critical | `webshell-antsword-proxy` | `/.antproxy.php` | AntSword Proxy Backdoor Present |
| 33 | critical | `webshell-aspx` | `/cmd.aspx` | ASPX Web Shell Present |
| 34 | critical | `webshell-b374k` | `/b374k.php` | b374k Web Shell Present |
| 35 | critical | `webshell-bypass` | `/bypass.php` | Symlink/Bypass Shell Present |
| 36 | critical | `webshell-c99` | `/c99.php` | C99 Web Shell Present |
| 37 | critical | `webshell-c99-alt` | `/images/c99.php` | C99 Web Shell Present (alt path) |
| 38 | critical | `webshell-cmd-php` | `/cmd.php` | Command-execution Shell Present |
| 39 | critical | `webshell-filesman` | `/filesman.php` | FilesMan Web Shell Present |
| 40 | critical | `webshell-generic-shell-php` | `/shell.php` | Generic PHP Web Shell Present |
| 41 | critical | `webshell-generic-uploads` | `/wp-content/uploads/shell.php` | Generic PHP Web Shell in uploads |
| 42 | critical | `webshell-indoxploit` | `/idx.php` | IndoXploit Web Shell Present |
| 43 | critical | `webshell-jsp` | `/cmd.jsp` | JSP Web Shell Present |
| 44 | critical | `webshell-marijuana` | `/marijuana.php` | Marijuana Web Shell Present |
| 45 | critical | `webshell-mini` | `/mini.php` | Mini Shell Present |
| 46 | critical | `webshell-p0wny` | `/p0wny.php` | p0wny Web Shell Present |
| 47 | critical | `webshell-phpshell` | `/phpshell.php` | PHP-Shell Console Present |
| 48 | critical | `webshell-priv8` | `/priv8.php` | Priv8 Web Shell Present |
| 49 | critical | `webshell-r57` | `/r57.php` | R57 Web Shell Present |
| 50 | critical | `webshell-uploader` | `/up.php` | File Uploader Backdoor Present |
| 51 | critical | `webshell-wordpress-plugin` | `/wp-content/plugins/hello.php` | Backdoored WordPress Plugin Shell |
| 52 | critical | `webshell-wp-config-decoy` | `/wp-content/wp-config.php` | Backdoor disguised as wp-config |
| 53 | critical | `webshell-wso` | `/wso.php` | WSO Web Shell Present |
| 54 | critical | `webshell-wso-upload` | `/wp-content/uploads/wso.php` | WSO Web Shell Present (uploads) |
| 55 | critical | `wp-config-bak` | `/wp-config.php.bak` | WordPress Config Backup Exposed |
| 56 | critical | `wp-install` | `/wp-admin/install.php?step=1` | WordPress Exposed Installation |
| 57 | critical | `wp-woocommerce-email-verification` | `/my-account/?alg_wc_ev_verify_email=eyJpZCI6MSwiY29kZSI6MH0=` | Email Verification for WooCommerce < 1.8.2 - Loose Comparison  |
| 58 | critical | `zipline-installer` | `/setup` | Zipline - Installer |
| 59 | high | `CVE-2023-49230` | `/cgi-bin/MANGA/index.cgi` | Peplink Balance Two before 8.4.0 - Unauthenticated Config Uplo |
| 60 | high | `CVE-2025-1232` | `/wp-json/wp/v2/pages?per_page=100` | Site Reviews < 7.2.5 - Unauthenticated Stored XSS |
| 61 | high | `CVE-2025-55523` | `/download_work_dir_file?path=/etc/passwd` | Agent-Zero 0.8.0 - 0.9.4 - Arbitrary File Download |
| 62 | high | `CVE-2026-4020` | `/wp-json/gravitysmtp/v1/tests/mock-data?page=gravitysmtp-settings` | Gravity SMTP WordPress Plugin - Sensitive Information Exposure |
| 63 | high | `adguard-installer` | `/install.html` | AdGuard - Installation |
| 64 | high | `adminer` | `/adminer.php` | Adminer Exposed |
| 65 | high | `administrate-dashboard` | `/admin` | Administrate Dashboard Exposure |
| 66 | high | `aem-explorer-nodetypes` | `/crx/explorer/nodetypes/index.jsp` | Adobe AEM Explorer NodeTypes Exposure |
| 67 | high | `aem-felix-console` | `/system/console/bundles` | Adobe Experience Manager Felix Console - Default Login |
| 68 | high | `apache-nifi-unauth` | `/nifi-api/access/config` | Apache NiFi - Unauthenticated Access |
| 69 | high | `apache-zeppelin-unauth` | `/api/security/ticket` | Apache Zeppelin - Unauthenticated Access |
| 70 | high | `artifactory-anonymous-deploy` | `/artifactory/ui/repodata?deploy=true` | Artifactory anonymous deploy |
| 71 | high | `asus-rtn16-default-login` | `/` | ASUS RT-N16 - Default Login |
| 72 | high | `atom-sync-remote` | `/.remote-sync.json` | Atom Synchronization Exposure |
| 73 | high | `auth-json` | `/auth.json` | Auth.json File - Disclosure |
| 74 | high | `avaya-phone-default-login` | `/cgi-bin/J100WebServer.cgi?Operation=0` | Avaya Phone Web Interface - Default Login |
| 75 | high | `azuracast-installer` | `/setup/register` | AzuraCast - Unfinished Installation |
| 76 | high | `brickcom-camera-unauth-snapshot` | `/ONVIF/media.cgi?action=getSnapshot` | Brickcom Camera - Unauthenticated Snapshot Access |
| 77 | high | `call-com-installer` | `/auth/setup` | Call.com Setup Page - Exposure |
| 78 | high | `clickhouse-unauth-api` | `/?query=SHOW%20DATABASES` | ClickHouse API Database Interface - Improper Authorization |
| 79 | high | `clockwork-dashboard-exposure` | `/__clockwork/latest` | Clockwork Dashboard Exposure |
| 80 | high | `collibra-properties` | `/collibra.properties` | Collibra Properties Exposure |
| 81 | high | `concrete-installer` | `/index.php/install` | Concrete Installer |
| 82 | high | `config-properties` | `/config.properties` | Config Properties Exposure |
| 83 | high | `confluence-installer` | `/setup/setupcluster-start.action` | Confluence Installation Page - Exposure |
| 84 | high | `connectwise-setup` | `/SetupWizard.aspx` | ConnectWise Setup Wizard - Exposure |
| 85 | high | `cube-105-install` | `/wizard/wizard.cs` | Cube-105 - Exposed Installation |
| 86 | high | `darkstat-detect` | `/darkstat/` | Detect Darkstat Reports |
| 87 | high | `dell-idrac-default-login` | `/login.html` | Dell iDRAC6/7/8 Default Login |
| 88 | high | `deos-openview-panel` | `/client/index.html` | DEOS OPENview Admin Panel Unauthenticated Access |
| 89 | high | `detect-drone-config` | `/.drone.yml` | Drone - Configuration Detection |
| 90 | high | `django-secret-key` | `/manage.py` | Django Secret Key Exposure |
| 91 | high | `docker-compose` | `/docker-compose.yml` | docker-compose.yml Exposed |
| 92 | high | `dockercfg-config` | `/.dockercfg` | Detect .dockercfg |
| 93 | high | `dot-credentials-exposure` | `/.credentials` | Dot Credentials - Exposure |
| 94 | high | `druid-monitor` | `/druid/index.html` | Alibaba Druid Monitor Unauthorized Access |
| 95 | high | `drupal-install` | `/install.php?profile=default` | Drupal Install |
| 96 | high | `easy-wi-installer` | `/install/install.php` | Easy-WI Installation Page - Exposure |
| 97 | high | `easyimage-downphp-lfi` | `/application/down.php?dw=config/config.php` | EasyImage down.php - Arbitrary File Read |
| 98 | high | `elasticsearch-default-login` | `/login` | ElasticSearch - Default Login |
| 99 | high | `elmah-log-file` | `/elmah` | ELMAH Exposure |
| 100 | high | `emlog-installer` | `/install.php` | Emlog Pro - Installation |
| 101 | high | `esmtprc-config` | `/.esmtprc` | eSMTP - Config Discovery |
| 102 | high | `eyoucms-installer` | `/install/index.php` | EyouCMS - Installation |
| 103 | high | `filestash-admin-config` | `/admin/setup` | Filestash Admin Password Configuration |
| 104 | high | `freescout-installer` | `/install` | FreeScout Installer Exposure |
| 105 | high | `freshrss-installer` | `/i/?rid` | FreshRSS - Installation |
| 106 | high | `freshrss-unauth` | `/i/?a=logs` | Freshrss Admin Dashboard - Exposed |
| 107 | high | `ftp-credentials-exposure` | `/ftpsync.settings` | FTP Credentials Exposure |
| 108 | high | `ftpconfig` | `/.ftpconfig` | Atom remote-ssh ftpconfig Exposure |
| 109 | high | `fusionauth-admin-setup` | `/admin/setup-wizard` | FusionAuth Exposed Admin Setup |
| 110 | high | `git-config` | `/.git/config` | Git Config Exposed |
| 111 | high | `git-head` | `/.git/HEAD` | Git HEAD Exposed |
| 112 | high | `gitlab-uninitialized-password` | `/users/sign_in` | Uninitialized GitLab instances |
| 113 | high | `gocd-cruise-configuration` | `/go/add-on/business-continuity/api/cruise_config` | GoCd Cruise Configuration disclosure |
| 114 | high | `growi-installer` | `/installer` | GROWI Installer - Exposure |
| 115 | high | `hikvision-env` | `/artemis/env` | Hikvision Springboot Env Actuator - Detect |
| 116 | high | `htpasswd-detection` | `/.htpasswd` | Apache htpasswd Config - Detect |
| 117 | high | `http-etcd-unauthenticated-api-data-leak` | `/v2/auth/roles` | etcd Unauthenticated HTTP API Leak |
| 118 | high | `http-etcd-unauthenticated-raft` | `/members` | etcd RAFT Unauthenticated API |
| 119 | high | `icinga-installer` | `/icingaweb2/setup` | Icinga Web 2 Installer Exposure |
| 120 | high | `invicti-enterprise-installer` | `/wizard/database/` | Invicti Enterprise Installation Page - Exposure |
| 121 | high | `jackett-installer` | `/configure` | Jackett - Installer |
| 122 | high | `jackett-unauth` | `/UI/Dashboard` | Jackett UI - Unauthenticated |
| 123 | high | `jenkins-panel` | `/` | Jenkins Dashboard Exposed |
| 124 | high | `kibana-panel` | `/app/kibana` | Kibana Dashboard Exposed |
| 125 | high | `laravel-log-file` | `/storage/logs/laravel.log` | Laravel log file publicly accessible |
| 126 | high | `laravel-nova-unauth` | `/nova/dashboards/main` | Laravel Nova - Unauthenticated Admin Panel Access |
| 127 | high | `laravel-passport-keys-exposed` | `/storage/oauth-private.key` | Laravel Passport - OAuth2 Keys Exposed |
| 128 | high | `laravel-sessions-exposure` | `/storage/framework/sessions/` | Laravel Sessions Folder Exposure |
| 129 | high | `laravel-terminal-exposure` | `/asf/terminal` | Laravel Terminal - Exposed |
| 130 | high | `librenms-installer` | `/install/checks` | LibreNMS Installation Page - Exposure |
| 131 | high | `lucee-unset-credentials` | `/lucee/admin/web.cfm` | Lucee - Unset Credentials |
| 132 | high | `lvmeng-uts-disclosure` | `/webapi/v1/system/accountmanage/account` | Lvmeng - UTS Disclosure |
| 133 | high | `magento-config-disclosure` | `/app/etc/local.xml` | Magento Configuration Panel - Detect |
| 134 | high | `magento-installer` | `/index.php/install/` | Magento Installation Wizard |
| 135 | high | `manage-engine-ad-search` | `/ADSearch.cc?methodToCall=search` | Manage Engine AD Search |
| 136 | high | `mlflow-unauth` | `/ajax-api/2.0/preview/mlflow/experiments/get?experiment_id=0` | Mlflow - Unauthenticated Access |
| 137 | high | `modx-installer` | `/setup/` | ModX CMS - Unfinished Installation |
| 138 | high | `msmtp-config` | `/.msmtprc` | Msmtp - Config Exposure |
| 139 | high | `mysql-config-exposure` | `/.my.cnf` | MySQL Conifg - Exposure |
| 140 | high | `nagios-logserver-installer` | `/nagioslogserver/install` | Nagios Log Server - Install |
| 141 | high | `onlyoffice-installer` | `/Wizard.aspx` | OnlyOffice Wizard Page - Exposure |
| 142 | high | `openbmcs-secret-disclosure` | `/debug/` | OpenBMCS 2.4 - Information Disclosure |
| 143 | high | `openemr-setup-installer` | `/setup.php` | OpenEMR Setup Installation Page - Exposure |
| 144 | high | `openfire-setup` | `/setup/index.jsp` | Openfire Setup - Exposure |
| 145 | high | `openstack-user-secrets` | `/user_secrets.yml` | OpenStack User Secrets Exposure |
| 146 | high | `orangehrm-installer` | `/installer/installerUI.php` | OrangeHrm Installer |
| 147 | high | `osticket-installer` | `/upload/setup/install.php` | osTicket Installer Panel - Detect |
| 148 | high | `parameters-config` | `/parameters.yml` | Parameters.yml - File Discovery |
| 149 | high | `pcoweb-unauth` | `/config/pw_left_bar.html` | pCOWeb - Unauth |
| 150 | high | `phalcon-framework-source` | `/anything_here` | Phalcon Framework - Source Code Leakage |
| 151 | high | `photoprism-unauth-exposure` | `/api/v1/config` | PhotoPrism - Unauthenticated Exposure |
| 152 | high | `php2shell-unpatched-php` | `/` | PHP Runtime Unpatched for php2shell RCE (CVE-2026-109618/10961 |
| 153 | high | `phpbb-installer` | `/install/app.php` | phpBB Installation File Exposure |
| 154 | high | `phpinfo` | `/phpinfo.php` | phpinfo() Exposed |
| 155 | high | `phpipam-installer` | `/index.php?page=install` | PHP IPAM Installation Page - Exposed |
| 156 | high | `phpmyadmin` | `/phpmyadmin/` | phpMyAdmin Exposed |
| 157 | high | `phpmyfaq-installer` | `/setup/index.php` | phpMyFAQ Installation - Exposure |
| 158 | high | `pmm-installer` | `/password-page/ovf/account-credentials-ovf` | PMM Installation Wizard |
| 159 | high | `poste-io-installer` | `/admin/install/server` | Poste.io - Installer |
| 160 | high | `private-key-exposure` | `/node_modules/mqtt/test/helpers/` | Private key exposure via helper detector |
| 161 | high | `profittrailer-installer` | `/setup/license` | ProfitTrailer Setup Page - Exposure |
| 162 | high | `prometheus-unauth` | `/config` | Prometheus Monitoring System - Unauthenticated |
| 163 | high | `qihang-media-disclosure` | `/xml/User/User.xml` | QiHang Media Web Digital Signage 3.0.9 - Cleartext Credentials |
| 164 | high | `rabbitmq-mgmt` | `/api/overview` | RabbitMQ Management Exposed |
| 165 | high | `rack-mini-profiler` | `/?pp=env` | rack-mini-profiler - Environment Information Disclosure |
| 166 | high | `rails-database-config` | `/config/database.yml` | Ruby on Rails Database Configuration File - Detect |
| 167 | high | `redmine-config` | `/configuration.yml` | Redmine Configuration File - Detect |
| 168 | high | `revive-adserver-installer` | `/www/admin/install.php?action=welcome` | Revive Adserver - Exposed Installer |
| 169 | high | `rexify-config-exposure` | `/Rexfile` | Rexify Configuration - Exposure |
| 170 | high | `robomongo-credential` | `/db/robomongo.json` | RoboMongo Credential - Exposure |
| 171 | high | `rubygems-credentials-exposure` | `/.gem/credentials` | Ruby Gem::ConfigFile Credential - Exposure |
| 172 | high | `ruckus-smartzone-install` | `/adminweb/` | Ruckus SmartZone Exposed Installation |
| 173 | high | `ruckus-unleashed-install` | `/admin/wizard.jsp` | Ruckus Unleashed Exposed Installation |
| 174 | high | `s3cfg-config` | `/.s3cfg` | S3CFG Configuration - Detect |
| 175 | high | `sabnzbd-installer` | `/sabnzbd/wizard/` | SABnzbd Quick-Start Wizard - Exposure |
| 176 | high | `saltbo-zpan-installer` | `/api/system/options/core.email` | Saltbo/zpan Installer - Exposure |
| 177 | high | `searchreplacedb2-exposure` | `/searchreplacedb2.php` | Safe Search Replace Exposure |
| 178 | high | `secnet-info-leak` | `/actpt_5g.data` | Secnet Intelligent Routing System actpt_5g.data - Information  |
| 179 | high | `selenium-exposure` | `/wd/hub` | Selenium - Node Exposure |
| 180 | high | `service-pwd` | `/_vti_pvt/service.pwd` | service.pwd - Sensitive Information Disclosure |
| 181 | high | `servicenow-title-injection` | `/login.do?jvar_page_title=<style><foo>Injected Title</foo></style>` | Service Now - Title Injection |
| 182 | high | `servicestack-requestlogs` | `/requestlogs` | ServiceStack Request Logs - Unauthenticated Access |
| 183 | high | `sftp-credentials-exposure` | `/sftp-config.json` | SFTP Configuration File - Credentials Exposure |
| 184 | high | `sftp-deployment-config` | `/deployment-config.json` | Atom SFTP Configuration File - Detect |
| 185 | high | `sftpgo-admin-setup` | `/web/admin/setup` | SFTPGo Admin - Setup |
| 186 | high | `shopware-installer` | `/public/recovery/install/index.php` | Shopware Installer |
| 187 | high | `sick-beard-xss` | `/config/postProcessing/testNaming?pattern=%3Csvg/onload=alert(document.domain)%3E` | Sickbeard - Cross-Site Scripting |
| 188 | high | `simatic-dashboard-exposed` | `/Portal0000.htm` | Siemens SIMATIC 300 Dashboard - Exposed |
| 189 | high | `socks5-vpn-config` | `/backup/config.xml` | Socks5 VPN - Sensitive File Disclosure |
| 190 | high | `solar-log-authbypass` | `/lan.html` | Solar-Log 500 2.8.2 - Incorrect Access Control |
| 191 | high | `sphinxsearch-config` | `/config/development.sphinx.conf` | Sphinx Search Config - Exposure |
| 192 | high | `spip-install` | `/ecrire/?exec=install` | SPIP Install - Exposure |
| 193 | high | `strongshop-installer` | `/install/index.html` | StrongShop Installer - Exposure |
| 194 | high | `symfony-database-config` | `/config/databases.yml` | Symfony Database Configuration File - Detect |
| 195 | high | `symfony-debug` | `/admin_dev.php` | Symfony Debug Mode |
| 196 | high | `symfony-profiler` | `/_profiler/empty/search/results?limit=10` | Symfony Profiler - Detect |
| 197 | high | `tasmota-install` | `/install/` | Tasmota Installer Exposure |
| 198 | high | `tautulli-install` | `/welcome` | Tautulli - Exposed Installation |
| 199 | high | `terraform-tfstate-exposure` | `/terraform.tfstate` | Terraform State - File Exposure |
| 200 | high | `testrail-install` | `/index.php?/installer` | TestRail Installation Wizard |
| 201 | high | `traefik-dashboard` | `/dashboard/` | Traefik Dashboard Exposed |
| 202 | high | `unauth-axyom-network-manager` | `/home` | Unauthenticated Axyom Network Manager |
| 203 | high | `unauth-ckfinder` | `/ckfinder/ckfinder.html` | CKFinder - Unauthenticated Exposure |
| 204 | high | `unauth-etcd-server` | `/v2/keys/` | Etcd Server - Unauthenticated Access |
| 205 | high | `unauth-hoteldruid-panel` | `/hoteldruid/inizio.php` | Hoteldruid Management Panel Access |
| 206 | high | `unauth-wavink-panel` | `/wifi_base.shtml` | Wavlink Panel - Unauthenticated Access |
| 207 | high | `unauthenticated-airflow-instance` | `/admin/` | Unauthenticated Airflow Instance |
| 208 | high | `unauthenticated-lansweeper` | `/Default.aspx` | Unauthenticated Lansweeper Instance |
| 209 | high | `unauthenticated-prtg` | `/sensorlist.htm` | PRTG Traffic Grapher - Unauthenticated Access |
| 210 | high | `unauthenticated-zipkin` | `/config.json` | Zipkin Discovery |
| 211 | high | `unauthorized-hp-printer` | `/SSI/Auth/ip_snmp.htm` | Unauthorized HP Printer |
| 212 | high | `unifi-wizard-install` | `/manage/wizard/` | UniFi Wizard Installer |
| 213 | high | `ventrilo-config` | `/ventrilo_srv.ini` | Ventrilo Configuration File - Detect |
| 214 | high | `wazuh-default-login` | `/app/login` | Wazuh - Default Login |
| 215 | high | `webmethod-integration-default-login` | `/invoke/pub.file/getFile` | WebMethod Integration Server Default Login |
| 216 | high | `webshell-adminer-drop` | `/adminer-4.8.1.php` | Adminer dropped as a shell |
| 217 | high | `wordpress-click2shell` | `/wp-admin/js/theme.js` | WordPress Click2Shell Theme Preview Selector Injection |
| 218 | high | `wordpress-total-upkeep-backup-download` | `/wp-content/plugins/boldgrid-backup/cron/restore-info.json` | WordPress Total Upkeep Database and Files Backup Download |
| 219 | high | `wp-config-setup` | `/wp-admin/setup-config.php?step=1` | WordPress Setup Configuration |
| 220 | high | `wpconfig-aws-keys` | `/wp-config.php.bak` | AWS S3 keys Leak |
| 221 | medium | `CVE-2024-13126` | `/wp-content/uploads/download-manager-files/` | WordPress Download Manager < 3.3.07 - Unauthenticated Data Exp |
| 222 | medium | `CVE-2024-30570` | `/debuginfo.htm` | Netgear R6850 - Information Disclosure |
| 223 | medium | `CVE-2024-45591` | `/xwiki/rest/wikis/xwiki/spaces/Main/pages/WebHome/history` | XWiki Platform - Unauthorized Document History Access |
| 224 | medium | `CVE-2024-54764` | `/login/hostinfo2.cgi` | ipTIME A2004 - Unauthorized Access |
| 225 | medium | `CVE-2025-58226` | `/wp-admin/admin-ajax.php?action=fb3d_send_posts` | WordPress 3D FlipBook Plugin <= 1.16.17 - Sensitive Informatio |
| 226 | medium | `CVE-2026-0717` | `/wp-json/lottiefiles/v1/settings/` | LottieFiles for Gutenberg <= 3.0.0 - Unauthenticated Settings  |
| 227 | medium | `CVE-2026-13153` | `/wp-json/essential-blocks/v1/products?per_page=20` | Essential Blocks < 6.4.0 - Information Disclosure |
| 228 | medium | `CVE-2026-27796` | `/api/trpc/integration.all` | Homarr < 1.54.0 - Information Disclosure |
| 229 | medium | `CVE-2026-29066` | `/etc/passwd` | TinaCMS - Path Traversal |
| 230 | medium | `CVE-2026-6826` | `/ccm/system/dialogs/file/usage/1` | Concrete CMS <9.5.1 - Unauthenticated File Usage Disclosure |
| 231 | medium | `CVE-2026-8236` | `/index.php/ccm/system/dialogs/file/usage/1` | Concrete CMS <9.5.1 - Unauthenticated File-Usage Internal Meta |
| 232 | medium | `aem-acs-common` | `/etc/acs-commons/jcr-compare.html` | Adobe AEM ACS Common Exposure |
| 233 | medium | `aem-dump-contentnode` | `/content.infinity.json` | AEM Dump Content Node Properties |
| 234 | medium | `aem-offloading-browser` | `/libs/granite/offloading/content/view.html` | Adobe AEM Offloading Browser |
| 235 | medium | `aem-security-users` | `/libs/granite/security/content/useradmin.html` | Adobe AEM Security Users Exposure |
| 236 | medium | `amr-printer-management-unauth` | `/amr` | AMR Printer Management Dashboard - Exposure |
| 237 | medium | `apache-hive-config` | `/conf` | Apache Hive Configuration - Exposure |
| 238 | medium | `apache-kyuubi-config` | `/engine-ui/0.0.0.0:4040/environment/` | Apache Kyuubi - Configuration Exposure |
| 239 | medium | `apache-pinot-config` | `/appconfigs` | Apache Pinot - Exposure |
| 240 | medium | `apache-polaris-metrics-exposure` | `/q/metrics` | Apache Polaris - Information Disclosure |
| 241 | medium | `apollo-adminservice-unauth` | `/apps` | Apollo Admin Service - Unauthenticated Access |
| 242 | medium | `appspec-yml-disclosure` | `/appspec.yml` | Appspec YML/YAML - Detect |
| 243 | medium | `appveyor-configuration-file` | `/.appveyor.yml` | AppVeyor Configuration Page - Detect |
| 244 | medium | `aspnet-launchsettings-exposure` | `/Properties/launchSettings.json` | ASP.NET Launch Settings - Exposure |
| 245 | medium | `aws-config` | `/.aws/config` | AWS Configuration - Detect |
| 246 | medium | `aws-s3-explorer` | `/index.html` | Amazon Web Services S3 Explorer - Detect |
| 247 | medium | `azure-functions-hostjson-exposure` | `/host.json` | Azure Functions host.json Configuration Exposure |
| 248 | medium | `azure-instrumentation-key-exposure` | `/appsettings.json` | Azure Instrumentation Key - Exposure |
| 249 | medium | `azure-pipelines-exposed` | `/.azure-pipelines.yml` | Azure Pipelines Configuration File Disclosure |
| 250 | medium | `behat-config` | `/behat.yml` | Behat Configuration File - Detect |
| 251 | medium | `bitrix-log-file-disclosure` | `/bitrix/modules/updater.log` | Bitrix Site Manager - Log File Disclosure |
| 252 | medium | `cacti-guest-access-enabled` | `/graph_view.php` | Cacti - Guest User Access Enabled |
| 253 | medium | `cacti-log-exposure` | `/cacti/log/cacti.log` | Cacti Log - Exposure |
| 254 | medium | `cgi-printenv` | `/cgi-bin/printenv.pl` | Test CGI Script - Detect |
| 255 | medium | `circleci-ssh-config` | `/.circleci/ssh-config` | CircleCI SSH Configuration - Detect |
| 256 | medium | `claude-settings-exposure` | `/.claude/settings.json` | Claude Code Project Settings Exposure |
| 257 | medium | `cloud-config` | `/cloud-config.yml` | Cloud Config File Exposure |
| 258 | medium | `cobbler-exposed-directory` | `/cobbler/` | Exposed Cobbler Directories |
| 259 | medium | `configuration-listing` | `/config/` | Sensitive Configuration Files Listing - Detect |
| 260 | medium | `coolify-register-account` | `/register` | Coolify Register User Account - Enabled |
| 261 | medium | `craftcms-log-disclosure` | `/storage/logs/web.log` | Craft CMS - Log File Disclosure |
| 262 | medium | `credentials-json` | `/credentials.json` | Credentials File Disclosure |
| 263 | medium | `db-xml-file` | `/db.xml` | db.xml File - Detect |
| 264 | medium | `docker-registry` | `/v2/_catalog` | Docker Registry Listing |
| 265 | medium | `ds-store` | `/.DS_Store` | .DS_Store Exposed |
| 266 | medium | `environment-rb` | `/environment.rb` | Environment Ruby File Disclosure |
| 267 | medium | `espeasy-installer` | `/ESPEasy` | ESPEasy Installation Exposure |
| 268 | medium | `exposed-alps-spring` | `/profile` | Exposed Spring Data REST Application-Level Profile Semantics ( |
| 269 | medium | `exposed-hg` | `/.hg/hgrc` | HG Configuration - Detect |
| 270 | medium | `exposed-nomad` | `/ui/jobs` | Nomad - Exposed Jobs |
| 271 | medium | `exposed-sharepoint-list` | `/_vti_bin/lists.asmx?WSDL` | Sharepoint List - Detect |
| 272 | medium | `firebase-config-exposure` | `/public/config.js` | Firebase Configuration File - Detect |
| 273 | medium | `flow-config-exposure` | `/.flowconfig` | Flow Configuration - Exposure |
| 274 | medium | `forgejo-repo-exposure` | `/explore/repos` | Forgejo Repositories - Exposure |
| 275 | medium | `gcloud-access-token` | `/access_tokens.db` | Google Cloud Access Token |
| 276 | medium | `gcloud-credentials` | `/credentials.db` | Google Cloud Credentials |
| 277 | medium | `generic-php-files` | `/settings.php.bak` | Generic PHP Backup Information Disclosure |
| 278 | medium | `git-config` | `/.git/config` | Git Configuration - Detect |
| 279 | medium | `git-credentials-disclosure` | `/.git-credentials` | Git Credentials - Detect |
| 280 | medium | `gitlab-ci-yml` | `/.gitlab-ci.yml` | GitLab CI YAML - Exposure |
| 281 | medium | `google-api-private-key` | `/google-api-private-key.json` | Google Api Private Key |
| 282 | medium | `grafana-loki-api-exposure` | `/loki/api/v1/labels` | Grafana Loki - Unauthenticated API Access |
| 283 | medium | `grafana-panel` | `/login` | Grafana Login Exposed |
| 284 | medium | `graphql-introspection` | `/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D` | GraphQL Introspection Enabled |
| 285 | medium | `haproxy-status` | `/haproxy-status` | HAProxy Statistics Page - Detect |
| 286 | medium | `hashicorp-consul-unauth` | `/v1/health/service/consul` | Hashicorp Consul API Unauthenticated |
| 287 | medium | `hazelcast-management-exposure` | `/hazelcast/rest/cluster` | Hazelcast Management Center - Configuration Exposure |
| 288 | medium | `hp-ilo-serial-key-disclosure` | `/xmldata?item=CpqKey` | HP iLO Serial Key - Detect |
| 289 | medium | `hp-laserjet-config` | `/hp/device/this.LCDispatcher?nav=hp.Config` | HP LaserJet Configuration Exposure |
| 290 | medium | `imprivata-installer` | `/wizard/base.php` | Imprivata Appliance Installation Exposure |
| 291 | medium | `info-cgi-env-leak` | `/info.cgi` | info.cgi  Environment Variable - Disclosure |
| 292 | medium | `jboss-seam-debug-page` | `/debug.seam` | Jboss Seam Debug Page Enabled |
| 293 | medium | `jellyfin-public-users-exposure` | `/Users/Public` | Jellyfin Public Users - Exposure |
| 294 | medium | `jenkins-openuser-register` | `/signup` | Jenkins Open User registration |
| 295 | medium | `jfrog-artifactory-build-exposure` | `/artifactory/api/build` | JFrog Artifactory Build - Exposure |
| 296 | medium | `joomla-file-listing` | `/libraries/joomla/database/` | Joomla! Database File List |
| 297 | medium | `karma-config-js` | `/.config/karma.conf.js` | Karma Configuration File - Detect |
| 298 | medium | `kubernetes-kustomization-disclosure` | `/kustomization.yml` | Kubernetes Kustomize Configuration - Detect |
| 299 | medium | `kyan-credential-exposure` | `/hosts` | Kyan Credential - Exposure |
| 300 | medium | `laravel-clockwork-exposure` | `/__clockwork` | Laravel Clockwork - Sensitive Information Exposure |
| 301 | medium | `laravel-debug-enabled` | `/_ignition/health-check` | Laravel Debug Enabled |
| 302 | medium | `laravel-debugbar-exposure` | `/_debugbar/open` | Laravel Debugbar - Sensitive Information Exposure |
| 303 | medium | `laravel-horizon-unauth` | `/api/stats` | Laravel Horizon Dashboard - Unauthenticated |
| 304 | medium | `laravel-ignition-log-viewer` | `/_ignition/logs` | Laravel Ignition - Log Viewer Information Disclosure |
| 305 | medium | `laravel-pulse-unauth` | `/pulse` | Laravel Pulse - Unauthenticated Dashboard Access |
| 306 | medium | `laravel-telescope` | `/telescope/requests` | Laravel Telescope Disclosure |
| 307 | medium | `lightstreamer-dashboard-exposure` | `/dashboard/` | Lightstreamer Dashboard Exposure |
| 308 | medium | `mailpit-app-info-disclosure` | `/api/v1/messages` | Mailpit App - Information Disclosure |
| 309 | medium | `mfp-unauth-exposure` | `/eSCL/ScannerCapabilities` | Multi-function Printer - Unauthorized Access |
| 310 | medium | `netalertx-dashboard` | `/devices.php` | NetAlert X Admin Dashboard - Exposed |
| 311 | medium | `nextgen-gallery-pro-error-log` | `/wp-content/debug.log` | WordPress NextGEN Gallery Pro - Error Log Disclosure |
| 312 | medium | `opcache-status-exposure` | `/opcache-status/` | OPcache Status Page - Detect |
| 313 | medium | `opencart-error-log` | `/system/storage/logs/error.log` | OpenCart Error Log Disclosure |
| 314 | medium | `opennms-dashboard-exposure` | `/opennms/index.jsp` | OpenNMS Dashboard - Exposure Detection |
| 315 | medium | `oracle-cgi-printenv` | `/cgi-bin/printenv` | Oracle CGI printenv - Information Disclosure |
| 316 | medium | `oracle-ebs-sqllog-exposure` | `/html/bin/sqlnet.log` | Oracle EBS SQL Log - Exposure |
| 317 | medium | `perfsonar-toolkit` | `/toolkit/` | perfSONAR Toolkit - Exposure |
| 318 | medium | `pghero-dashboard-exposure` | `/connections` | PgHero Dashboard Exposure Panel - Detect |
| 319 | medium | `phinx-config` | `/phinx.yml` | Phinx Configuration Exposure |
| 320 | medium | `php-eol-runtime` | `/` | End-of-Life PHP Runtime (no security updates) |
| 321 | medium | `php-user-ini-disclosure` | `/user.ini` | Php User.ini Disclosure |
| 322 | medium | `plesk-stat` | `/plesk-stat/` | Webalizer Log Analyzer Configuration - Detect |
| 323 | medium | `prisma-schema-exposure` | `/schema.prisma` | Exposed Prisma Database Schema - Exposure |
| 324 | medium | `prometheus-metrics` | `/metrics` | Prometheus Metrics Exposed |
| 325 | medium | `prometheus-metrics` | `/metrics` | Prometheus Metrics - Detect |
| 326 | medium | `prometheus-promtail` | `/service-discovery` | Prometheus Promtail - Exposure |
| 327 | medium | `putty-private-key-disclosure` | `/my.ppk` | Putty Private Key Disclosure |
| 328 | medium | `pyramid-debug-toolbar` | `/_debug_toolbar/` | Pyramid Debug Toolbar |
| 329 | medium | `rails-secret-token-disclosure` | `/config/initializers/secret_token.rb` | Ruby on Rails Secret Token Disclosure |
| 330 | medium | `redis-config` | `/redis.conf` | Redis Configuration File - Detect |
| 331 | medium | `redmine-issues-exposure` | `/issues.json` | Redmine Issues - Exposure |
| 332 | medium | `redpanda-console` | `/overview` | Redpanda Console - Exposure |
| 333 | medium | `secret-token-rb` | `/secret_token.rb` | Secret Token Ruby - File Disclosure |
| 334 | medium | `sensitive-storage-data-expose` | `/storage/` | Sensitive Storage Data - Detect |
| 335 | medium | `service-account-credentials` | `/assets/other/service-account-credentials.json` | Service Account Credentials File Disclosure |
| 336 | medium | `slurm-hpc-dashboard` | `/slurm/` | Slurm HPC Dashboard - Detect |
| 337 | medium | `sonarqube` | `/api/system/status` | SonarQube Exposed |
| 338 | medium | `sonarqube-projects-disclosure` | `/api/components/search_projects` | SonarQube - Information Disclosure |
| 339 | medium | `sound4-directory-listing` | `/log/` | SOUND4 Impact/Pulse/First/Eco <=2.x - Information Disclosure |
| 340 | medium | `springboot-gateway` | `/gateway/routes` | Detect Spring Gateway Actuator |
| 341 | medium | `ssh-authorized-keys` | `/.ssh/authorized_keys` | SSH Authorized Keys File - Detect |
| 342 | medium | `svn-wc-db` | `/.svn/wc.db` | SVN wc.db File Exposure |
| 343 | medium | `swagger-spec` | `/swagger.json` | Swagger/OpenAPI Spec Exposed |
| 344 | medium | `tcpconfig` | `/tcpconfig.html` | Rockwell Automation TCP/IP Configuration Information - Detect |
| 345 | medium | `teampass-ldap` | `/files/ldap.debug.txt` | Teampass LDAP Debug Config - Detect |
| 346 | medium | `teslamate-unauth-access` | `/settings` | TeslaMate - Unauthenticated Access |
| 347 | medium | `transmission-dashboard` | `/transmission/web/` | Transmission Dashboard - Detect |
| 348 | medium | `unauth-fastvue-dashboard` | `/dashboard.aspx` | Fastvue Dashboard Panel - Unauthenticated Detect |
| 349 | medium | `unauthenticated-duplicator-disclosure` | `/wp-content/backups-dup-lite/tmp/` | WordPress Duplicator Plugin - Information disclosure |
| 350 | medium | `untangle-admin-setup` | `/setup/setup.do` | Untangle Exposed Admin Signup |
| 351 | medium | `vercel-source-exposure` | `/_src` | Vercel Source Code Exposure |
| 352 | medium | `wordfence-config-disclosure` | `/wp-content/wflogs/config.php` | WordPress Wordfence - Configuration File Disclosure |
| 353 | medium | `wordfence-rules-disclosure` | `/wp-content/wflogs/rules.php` | WordPress Wordfence - Rules File Disclosure |
| 354 | medium | `wp-user-enum` | `/wp-json/wp/v2/users` | WordPress User Enumeration |
| 355 | medium | `xprober-service` | `/xprober.php` | X Prober Server - Information Disclosure |
| 356 | medium | `zabbix-dashboards-access` | `/zabbix/zabbix.php?action=dashboard.list` | zabbix-dashboards-access |
| 357 | medium | `zen-cart-log-exposure` | `/logs/` | Zen Cart Log File Exposure |
| 358 | low | `3cx-config` | `/SetupConfig.xml` | 3CX Config - File Disclosure |
| 359 | low | `aem-osgi-bundles` | `/bin.tidy.infinity.json` | Adobe AEM Installed OSGI Bundles |
| 360 | low | `airflow-debug` | `/admin/airflow/login` | Airflow Debug Trace |
| 361 | low | `codeception-config` | `/codeception.yml` | Codeception YAML Configuration File - Detect |
| 362 | low | `database-credentials` | `/database_credentials.inc` | Database Credentials File Exposure |
| 363 | low | `debug-vars` | `/debug/vars` | Golang Expvar - Detect |
| 364 | low | `dlink-unauth-cgi-script` | `/cgi-bin/info.cgi` | D-Link DNS Series  CGI Script - Unauthenticated |
| 365 | low | `domcfg-page` | `/domcfg.nsf` | Lotus Domino Configuration Page |
| 366 | low | `drupal-directory-listing` | `/sites/` | Drupal Directory Listing |
| 367 | low | `editor-exposure` | `/.editorconfig` | Editor Configuration File - Detect |
| 368 | low | `elasticsearch` | `/_cluster/health?pretty` | ElasticSearch Information Disclosure |
| 369 | low | `exposed-bitkeeper` | `/BitKeeper/etc/config` | BitKeeper Configuration - Detect |
| 370 | low | `firebase-debug-log` | `/firebase-debug.log` | Firebase Debug Log File Exposure |
| 371 | low | `firebase-detect` | `/.settings/rules.json?auth=FIREBASE_SECRET` | firebase detect |
| 372 | low | `go-pprof-debug` | `/debug/pprof/heap?debug=1` | Go pprof Debug Page |
| 373 | low | `imageresizer-debug-exposure` | `/resizer.debug.ashx` | ImageResizer Debug - Information Exposure |
| 374 | low | `intelbras-dvr-unauth` | `/cap.js` | Intelbras DVR - Unrestricted Access |
| 375 | low | `javascript-env` | `/env.js` | JavaScript Environment Configuration - Detect |
| 376 | low | `jfrog-artifactory-exposure` | `/artifactory/api/repositories` | JFrog Artifactory Artifacts Exposure |
| 377 | low | `joomla-config-dist-file` | `/configuration.php-dist` | Joomla! Configuration File - Detect |
| 378 | low | `joomla-fpd` | `/administrator/manifests/files/joomla.xml` | Joomla! - Full Path Disclosure |
| 379 | low | `keycloak-admin-console-config` | `/admin/master/console/config` | Keycloak Admin Console Configuration Disclosure |
| 380 | low | `librechat-config-exposure` | `/api/config` | librechat - Config Exposure |
| 381 | low | `ms-front-page-misconfig` | `/_vti_inf.html` | Microsoft FrontPage Configuration - Exposure |
| 382 | low | `npm-debug-log` | `/npm-debug.log` | NPM Debug Log Disclosure |
| 383 | low | `oauth-credentials-json` | `/oauth-credentials.json` | Oauth Credentials Json |
| 384 | low | `openstack-config` | `/info` | Openstack - Infomation Disclosure |
| 385 | low | `platformio-ini` | `/platformio.ini` | Platformio Config File Disclosure |
| 386 | low | `prometheus-log` | `/prometheus` | Exposed Prometheus |
| 387 | low | `protractor-config` | `/protractor.conf.js` | Protractor Configuration Exposure |
| 388 | low | `psalm-config` | `/psalm.xml` | Psalm Configuration Exposure - Detect |
| 389 | low | `python-setup-config` | `/setup.py` | Python Setup Configuration - Exposure |
| 390 | low | `ruijie-phpinfo` | `/tool/view/phpinfo.view.php` | Ruijie Phpinfo Configuration - Detect |
| 391 | low | `shell-history` | `/.bash_history` | Shell History |
| 392 | low | `sitecore-debug-page` | `/sitecore/'` | SiteCore Debug Page |
| 393 | low | `sonarqube-public-projects` | `/api/components/suggestions?recentlyBrowsed=` | Sonarqube with public projects |
| 394 | low | `springboot-autoconfig` | `/autoconfig` | Detect Springboot autoconfig Actuator |
| 395 | low | `springboot-beans` | `/beans` | Detect Springboot Beans Actuator |
| 396 | low | `springboot-caches` | `/caches` | Springboot Actuator Caches |
| 397 | low | `springboot-conditions` | `/conditions` | Detect Springboot Conditions Actuator |
| 398 | low | `springboot-configprops` | `/configprops` | Detect Springboot Configprops Actuator |
| 399 | low | `springboot-dump` | `/dump` | Detect Springboot Dump Actuator |
| 400 | low | `springboot-env` | `/env` | Springboot Env Actuator - Detect |
| 401 | low | `springboot-features` | `/features` | Detects Springboot Features Actuator |
| 402 | low | `springboot-flyway` | `/flyway` | Springboot Flyway API |
| 403 | low | `springboot-httpexchanges` | `/httpexchanges` | Detects Springboot HTTP Exchanges Actuator |
| 404 | low | `springboot-httptrace` | `/httptrace` | Detect Springboot httptrace |
| 405 | low | `springboot-integrationgraph` | `/integrationgraph` | Springboot Actuator integrationgraph |
| 406 | low | `springboot-jolokia` | `/jolokia` | Detects Springboot Jolokia Actuator |
| 407 | low | `springboot-liquidbase` | `/liquibase` | Springboot Liquidbase API |
| 408 | low | `springboot-logfile` | `/logfile` | Detects Springboot Logfile Actuator |
| 409 | low | `springboot-loggers` | `/loggers` | Springboot Loggers - Exposure |
| 410 | low | `springboot-sbom` | `/sbom` | Spring Boot Actuator SBOM - Exposure |
| 411 | low | `springboot-startup` | `/startup` | Springboot Actuator startup |
| 412 | low | `springboot-threaddump` | `/threaddump` | Detect Springboot Thread Dump page |
| 413 | low | `token-json` | `/token.json` | Token Json File Disclosure |
| 414 | low | `tomcat-cookie-exposed` | `/examples/servlets/servlet/CookieExample` | Tomcat Cookie Exposed |
| 415 | low | `umbraco-miniprofiler-exposure` | `/mini-profiler-resources/results` | Umbraco Mini Profiler - Exposure |
| 416 | low | `unauthenticated-nginx-dashboard` | `/dashboard.html` | Nginx Dashboard |
| 417 | low | `victoriametrics-vmagent-api-exposure` | `/api/v1/targets` | VictoriaMetrics vmagent - Unauthenticated Targets Exposure |
| 418 | low | `vscode-mcp-json` | `/mcp.json` | Visual Studio Code MCP Configuration ("mcp.json") Exposure |
| 419 | low | `wordpress-wp-env-exposure` | `/.wp-env.json` | WordPress Configuration wp-env - Exposure |
| 420 | low | `yii-debugger` | `/debug/default/view.html` | View Yii Debugger Information |

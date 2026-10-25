# Kumo vulnerability playbook

**418 rules.** Every one is a GET plus a response signature: Kumo probes a path and matches evidence in the reply. No rule sends a payload, executes anything, or interacts with what it finds.

Each is validated by `test_rules.py` against 11 decoy responses, and the dead-rule check proves its evidence survives its own path scrub.

| severity | count |
|---|---|
| critical | 58 |
| high | 161 |
| medium | 136 |
| low | 63 |

**Origin:** nuclei 338, handwritten 30, kumo-webshell 27, nuclei-unauth 23

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
| 152 | high | `phpbb-installer` | `/install/app.php` | phpBB Installation File Exposure |
| 153 | high | `phpinfo` | `/phpinfo.php` | phpinfo() Exposed |
| 154 | high | `phpipam-installer` | `/index.php?page=install` | PHP IPAM Installation Page - Exposed |
| 155 | high | `phpmyadmin` | `/phpmyadmin/` | phpMyAdmin Exposed |
| 156 | high | `phpmyfaq-installer` | `/setup/index.php` | phpMyFAQ Installation - Exposure |
| 157 | high | `pmm-installer` | `/password-page/ovf/account-credentials-ovf` | PMM Installation Wizard |
| 158 | high | `poste-io-installer` | `/admin/install/server` | Poste.io - Installer |
| 159 | high | `private-key-exposure` | `/node_modules/mqtt/test/helpers/` | Private key exposure via helper detector |
| 160 | high | `profittrailer-installer` | `/setup/license` | ProfitTrailer Setup Page - Exposure |
| 161 | high | `prometheus-unauth` | `/config` | Prometheus Monitoring System - Unauthenticated |
| 162 | high | `qihang-media-disclosure` | `/xml/User/User.xml` | QiHang Media Web Digital Signage 3.0.9 - Cleartext Credentials |
| 163 | high | `rabbitmq-mgmt` | `/api/overview` | RabbitMQ Management Exposed |
| 164 | high | `rack-mini-profiler` | `/?pp=env` | rack-mini-profiler - Environment Information Disclosure |
| 165 | high | `rails-database-config` | `/config/database.yml` | Ruby on Rails Database Configuration File - Detect |
| 166 | high | `redmine-config` | `/configuration.yml` | Redmine Configuration File - Detect |
| 167 | high | `revive-adserver-installer` | `/www/admin/install.php?action=welcome` | Revive Adserver - Exposed Installer |
| 168 | high | `rexify-config-exposure` | `/Rexfile` | Rexify Configuration - Exposure |
| 169 | high | `robomongo-credential` | `/db/robomongo.json` | RoboMongo Credential - Exposure |
| 170 | high | `rubygems-credentials-exposure` | `/.gem/credentials` | Ruby Gem::ConfigFile Credential - Exposure |
| 171 | high | `ruckus-smartzone-install` | `/adminweb/` | Ruckus SmartZone Exposed Installation |
| 172 | high | `ruckus-unleashed-install` | `/admin/wizard.jsp` | Ruckus Unleashed Exposed Installation |
| 173 | high | `s3cfg-config` | `/.s3cfg` | S3CFG Configuration - Detect |
| 174 | high | `sabnzbd-installer` | `/sabnzbd/wizard/` | SABnzbd Quick-Start Wizard - Exposure |
| 175 | high | `saltbo-zpan-installer` | `/api/system/options/core.email` | Saltbo/zpan Installer - Exposure |
| 176 | high | `searchreplacedb2-exposure` | `/searchreplacedb2.php` | Safe Search Replace Exposure |
| 177 | high | `secnet-info-leak` | `/actpt_5g.data` | Secnet Intelligent Routing System actpt_5g.data - Information  |
| 178 | high | `selenium-exposure` | `/wd/hub` | Selenium - Node Exposure |
| 179 | high | `service-pwd` | `/_vti_pvt/service.pwd` | service.pwd - Sensitive Information Disclosure |
| 180 | high | `servicenow-title-injection` | `/login.do?jvar_page_title=<style><foo>Injected Title</foo></style>` | Service Now - Title Injection |
| 181 | high | `servicestack-requestlogs` | `/requestlogs` | ServiceStack Request Logs - Unauthenticated Access |
| 182 | high | `sftp-credentials-exposure` | `/sftp-config.json` | SFTP Configuration File - Credentials Exposure |
| 183 | high | `sftp-deployment-config` | `/deployment-config.json` | Atom SFTP Configuration File - Detect |
| 184 | high | `sftpgo-admin-setup` | `/web/admin/setup` | SFTPGo Admin - Setup |
| 185 | high | `shopware-installer` | `/public/recovery/install/index.php` | Shopware Installer |
| 186 | high | `sick-beard-xss` | `/config/postProcessing/testNaming?pattern=%3Csvg/onload=alert(document.domain)%3E` | Sickbeard - Cross-Site Scripting |
| 187 | high | `simatic-dashboard-exposed` | `/Portal0000.htm` | Siemens SIMATIC 300 Dashboard - Exposed |
| 188 | high | `socks5-vpn-config` | `/backup/config.xml` | Socks5 VPN - Sensitive File Disclosure |
| 189 | high | `solar-log-authbypass` | `/lan.html` | Solar-Log 500 2.8.2 - Incorrect Access Control |
| 190 | high | `sphinxsearch-config` | `/config/development.sphinx.conf` | Sphinx Search Config - Exposure |
| 191 | high | `spip-install` | `/ecrire/?exec=install` | SPIP Install - Exposure |
| 192 | high | `strongshop-installer` | `/install/index.html` | StrongShop Installer - Exposure |
| 193 | high | `symfony-database-config` | `/config/databases.yml` | Symfony Database Configuration File - Detect |
| 194 | high | `symfony-debug` | `/admin_dev.php` | Symfony Debug Mode |
| 195 | high | `symfony-profiler` | `/_profiler/empty/search/results?limit=10` | Symfony Profiler - Detect |
| 196 | high | `tasmota-install` | `/install/` | Tasmota Installer Exposure |
| 197 | high | `tautulli-install` | `/welcome` | Tautulli - Exposed Installation |
| 198 | high | `terraform-tfstate-exposure` | `/terraform.tfstate` | Terraform State - File Exposure |
| 199 | high | `testrail-install` | `/index.php?/installer` | TestRail Installation Wizard |
| 200 | high | `traefik-dashboard` | `/dashboard/` | Traefik Dashboard Exposed |
| 201 | high | `unauth-axyom-network-manager` | `/home` | Unauthenticated Axyom Network Manager |
| 202 | high | `unauth-ckfinder` | `/ckfinder/ckfinder.html` | CKFinder - Unauthenticated Exposure |
| 203 | high | `unauth-etcd-server` | `/v2/keys/` | Etcd Server - Unauthenticated Access |
| 204 | high | `unauth-hoteldruid-panel` | `/hoteldruid/inizio.php` | Hoteldruid Management Panel Access |
| 205 | high | `unauth-wavink-panel` | `/wifi_base.shtml` | Wavlink Panel - Unauthenticated Access |
| 206 | high | `unauthenticated-airflow-instance` | `/admin/` | Unauthenticated Airflow Instance |
| 207 | high | `unauthenticated-lansweeper` | `/Default.aspx` | Unauthenticated Lansweeper Instance |
| 208 | high | `unauthenticated-prtg` | `/sensorlist.htm` | PRTG Traffic Grapher - Unauthenticated Access |
| 209 | high | `unauthenticated-zipkin` | `/config.json` | Zipkin Discovery |
| 210 | high | `unauthorized-hp-printer` | `/SSI/Auth/ip_snmp.htm` | Unauthorized HP Printer |
| 211 | high | `unifi-wizard-install` | `/manage/wizard/` | UniFi Wizard Installer |
| 212 | high | `ventrilo-config` | `/ventrilo_srv.ini` | Ventrilo Configuration File - Detect |
| 213 | high | `wazuh-default-login` | `/app/login` | Wazuh - Default Login |
| 214 | high | `webmethod-integration-default-login` | `/invoke/pub.file/getFile` | WebMethod Integration Server Default Login |
| 215 | high | `webshell-adminer-drop` | `/adminer-4.8.1.php` | Adminer dropped as a shell |
| 216 | high | `wordpress-click2shell` | `/wp-admin/js/theme.js` | WordPress Click2Shell Theme Preview Selector Injection |
| 217 | high | `wordpress-total-upkeep-backup-download` | `/wp-content/plugins/boldgrid-backup/cron/restore-info.json` | WordPress Total Upkeep Database and Files Backup Download |
| 218 | high | `wp-config-setup` | `/wp-admin/setup-config.php?step=1` | WordPress Setup Configuration |
| 219 | high | `wpconfig-aws-keys` | `/wp-config.php.bak` | AWS S3 keys Leak |
| 220 | medium | `CVE-2024-13126` | `/wp-content/uploads/download-manager-files/` | WordPress Download Manager < 3.3.07 - Unauthenticated Data Exp |
| 221 | medium | `CVE-2024-30570` | `/debuginfo.htm` | Netgear R6850 - Information Disclosure |
| 222 | medium | `CVE-2024-45591` | `/xwiki/rest/wikis/xwiki/spaces/Main/pages/WebHome/history` | XWiki Platform - Unauthorized Document History Access |
| 223 | medium | `CVE-2024-54764` | `/login/hostinfo2.cgi` | ipTIME A2004 - Unauthorized Access |
| 224 | medium | `CVE-2025-58226` | `/wp-admin/admin-ajax.php?action=fb3d_send_posts` | WordPress 3D FlipBook Plugin <= 1.16.17 - Sensitive Informatio |
| 225 | medium | `CVE-2026-0717` | `/wp-json/lottiefiles/v1/settings/` | LottieFiles for Gutenberg <= 3.0.0 - Unauthenticated Settings  |
| 226 | medium | `CVE-2026-13153` | `/wp-json/essential-blocks/v1/products?per_page=20` | Essential Blocks < 6.4.0 - Information Disclosure |
| 227 | medium | `CVE-2026-27796` | `/api/trpc/integration.all` | Homarr < 1.54.0 - Information Disclosure |
| 228 | medium | `CVE-2026-29066` | `/etc/passwd` | TinaCMS - Path Traversal |
| 229 | medium | `CVE-2026-6826` | `/ccm/system/dialogs/file/usage/1` | Concrete CMS <9.5.1 - Unauthenticated File Usage Disclosure |
| 230 | medium | `CVE-2026-8236` | `/index.php/ccm/system/dialogs/file/usage/1` | Concrete CMS <9.5.1 - Unauthenticated File-Usage Internal Meta |
| 231 | medium | `aem-acs-common` | `/etc/acs-commons/jcr-compare.html` | Adobe AEM ACS Common Exposure |
| 232 | medium | `aem-dump-contentnode` | `/content.infinity.json` | AEM Dump Content Node Properties |
| 233 | medium | `aem-offloading-browser` | `/libs/granite/offloading/content/view.html` | Adobe AEM Offloading Browser |
| 234 | medium | `aem-security-users` | `/libs/granite/security/content/useradmin.html` | Adobe AEM Security Users Exposure |
| 235 | medium | `amr-printer-management-unauth` | `/amr` | AMR Printer Management Dashboard - Exposure |
| 236 | medium | `apache-hive-config` | `/conf` | Apache Hive Configuration - Exposure |
| 237 | medium | `apache-kyuubi-config` | `/engine-ui/0.0.0.0:4040/environment/` | Apache Kyuubi - Configuration Exposure |
| 238 | medium | `apache-pinot-config` | `/appconfigs` | Apache Pinot - Exposure |
| 239 | medium | `apache-polaris-metrics-exposure` | `/q/metrics` | Apache Polaris - Information Disclosure |
| 240 | medium | `apollo-adminservice-unauth` | `/apps` | Apollo Admin Service - Unauthenticated Access |
| 241 | medium | `appspec-yml-disclosure` | `/appspec.yml` | Appspec YML/YAML - Detect |
| 242 | medium | `appveyor-configuration-file` | `/.appveyor.yml` | AppVeyor Configuration Page - Detect |
| 243 | medium | `aspnet-launchsettings-exposure` | `/Properties/launchSettings.json` | ASP.NET Launch Settings - Exposure |
| 244 | medium | `aws-config` | `/.aws/config` | AWS Configuration - Detect |
| 245 | medium | `aws-s3-explorer` | `/index.html` | Amazon Web Services S3 Explorer - Detect |
| 246 | medium | `azure-functions-hostjson-exposure` | `/host.json` | Azure Functions host.json Configuration Exposure |
| 247 | medium | `azure-instrumentation-key-exposure` | `/appsettings.json` | Azure Instrumentation Key - Exposure |
| 248 | medium | `azure-pipelines-exposed` | `/.azure-pipelines.yml` | Azure Pipelines Configuration File Disclosure |
| 249 | medium | `behat-config` | `/behat.yml` | Behat Configuration File - Detect |
| 250 | medium | `bitrix-log-file-disclosure` | `/bitrix/modules/updater.log` | Bitrix Site Manager - Log File Disclosure |
| 251 | medium | `cacti-guest-access-enabled` | `/graph_view.php` | Cacti - Guest User Access Enabled |
| 252 | medium | `cacti-log-exposure` | `/cacti/log/cacti.log` | Cacti Log - Exposure |
| 253 | medium | `cgi-printenv` | `/cgi-bin/printenv.pl` | Test CGI Script - Detect |
| 254 | medium | `circleci-ssh-config` | `/.circleci/ssh-config` | CircleCI SSH Configuration - Detect |
| 255 | medium | `claude-settings-exposure` | `/.claude/settings.json` | Claude Code Project Settings Exposure |
| 256 | medium | `cloud-config` | `/cloud-config.yml` | Cloud Config File Exposure |
| 257 | medium | `cobbler-exposed-directory` | `/cobbler/` | Exposed Cobbler Directories |
| 258 | medium | `configuration-listing` | `/config/` | Sensitive Configuration Files Listing - Detect |
| 259 | medium | `coolify-register-account` | `/register` | Coolify Register User Account - Enabled |
| 260 | medium | `craftcms-log-disclosure` | `/storage/logs/web.log` | Craft CMS - Log File Disclosure |
| 261 | medium | `credentials-json` | `/credentials.json` | Credentials File Disclosure |
| 262 | medium | `db-xml-file` | `/db.xml` | db.xml File - Detect |
| 263 | medium | `docker-registry` | `/v2/_catalog` | Docker Registry Listing |
| 264 | medium | `ds-store` | `/.DS_Store` | .DS_Store Exposed |
| 265 | medium | `environment-rb` | `/environment.rb` | Environment Ruby File Disclosure |
| 266 | medium | `espeasy-installer` | `/ESPEasy` | ESPEasy Installation Exposure |
| 267 | medium | `exposed-alps-spring` | `/profile` | Exposed Spring Data REST Application-Level Profile Semantics ( |
| 268 | medium | `exposed-hg` | `/.hg/hgrc` | HG Configuration - Detect |
| 269 | medium | `exposed-nomad` | `/ui/jobs` | Nomad - Exposed Jobs |
| 270 | medium | `exposed-sharepoint-list` | `/_vti_bin/lists.asmx?WSDL` | Sharepoint List - Detect |
| 271 | medium | `firebase-config-exposure` | `/public/config.js` | Firebase Configuration File - Detect |
| 272 | medium | `flow-config-exposure` | `/.flowconfig` | Flow Configuration - Exposure |
| 273 | medium | `forgejo-repo-exposure` | `/explore/repos` | Forgejo Repositories - Exposure |
| 274 | medium | `gcloud-access-token` | `/access_tokens.db` | Google Cloud Access Token |
| 275 | medium | `gcloud-credentials` | `/credentials.db` | Google Cloud Credentials |
| 276 | medium | `generic-php-files` | `/settings.php.bak` | Generic PHP Backup Information Disclosure |
| 277 | medium | `git-config` | `/.git/config` | Git Configuration - Detect |
| 278 | medium | `git-credentials-disclosure` | `/.git-credentials` | Git Credentials - Detect |
| 279 | medium | `gitlab-ci-yml` | `/.gitlab-ci.yml` | GitLab CI YAML - Exposure |
| 280 | medium | `google-api-private-key` | `/google-api-private-key.json` | Google Api Private Key |
| 281 | medium | `grafana-loki-api-exposure` | `/loki/api/v1/labels` | Grafana Loki - Unauthenticated API Access |
| 282 | medium | `grafana-panel` | `/login` | Grafana Login Exposed |
| 283 | medium | `graphql-introspection` | `/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D` | GraphQL Introspection Enabled |
| 284 | medium | `haproxy-status` | `/haproxy-status` | HAProxy Statistics Page - Detect |
| 285 | medium | `hashicorp-consul-unauth` | `/v1/health/service/consul` | Hashicorp Consul API Unauthenticated |
| 286 | medium | `hazelcast-management-exposure` | `/hazelcast/rest/cluster` | Hazelcast Management Center - Configuration Exposure |
| 287 | medium | `hp-ilo-serial-key-disclosure` | `/xmldata?item=CpqKey` | HP iLO Serial Key - Detect |
| 288 | medium | `hp-laserjet-config` | `/hp/device/this.LCDispatcher?nav=hp.Config` | HP LaserJet Configuration Exposure |
| 289 | medium | `imprivata-installer` | `/wizard/base.php` | Imprivata Appliance Installation Exposure |
| 290 | medium | `info-cgi-env-leak` | `/info.cgi` | info.cgi  Environment Variable - Disclosure |
| 291 | medium | `jboss-seam-debug-page` | `/debug.seam` | Jboss Seam Debug Page Enabled |
| 292 | medium | `jellyfin-public-users-exposure` | `/Users/Public` | Jellyfin Public Users - Exposure |
| 293 | medium | `jenkins-openuser-register` | `/signup` | Jenkins Open User registration |
| 294 | medium | `jfrog-artifactory-build-exposure` | `/artifactory/api/build` | JFrog Artifactory Build - Exposure |
| 295 | medium | `joomla-file-listing` | `/libraries/joomla/database/` | Joomla! Database File List |
| 296 | medium | `karma-config-js` | `/.config/karma.conf.js` | Karma Configuration File - Detect |
| 297 | medium | `kubernetes-kustomization-disclosure` | `/kustomization.yml` | Kubernetes Kustomize Configuration - Detect |
| 298 | medium | `kyan-credential-exposure` | `/hosts` | Kyan Credential - Exposure |
| 299 | medium | `laravel-clockwork-exposure` | `/__clockwork` | Laravel Clockwork - Sensitive Information Exposure |
| 300 | medium | `laravel-debug-enabled` | `/_ignition/health-check` | Laravel Debug Enabled |
| 301 | medium | `laravel-debugbar-exposure` | `/_debugbar/open` | Laravel Debugbar - Sensitive Information Exposure |
| 302 | medium | `laravel-horizon-unauth` | `/api/stats` | Laravel Horizon Dashboard - Unauthenticated |
| 303 | medium | `laravel-ignition-log-viewer` | `/_ignition/logs` | Laravel Ignition - Log Viewer Information Disclosure |
| 304 | medium | `laravel-pulse-unauth` | `/pulse` | Laravel Pulse - Unauthenticated Dashboard Access |
| 305 | medium | `laravel-telescope` | `/telescope/requests` | Laravel Telescope Disclosure |
| 306 | medium | `lightstreamer-dashboard-exposure` | `/dashboard/` | Lightstreamer Dashboard Exposure |
| 307 | medium | `mailpit-app-info-disclosure` | `/api/v1/messages` | Mailpit App - Information Disclosure |
| 308 | medium | `mfp-unauth-exposure` | `/eSCL/ScannerCapabilities` | Multi-function Printer - Unauthorized Access |
| 309 | medium | `netalertx-dashboard` | `/devices.php` | NetAlert X Admin Dashboard - Exposed |
| 310 | medium | `nextgen-gallery-pro-error-log` | `/wp-content/debug.log` | WordPress NextGEN Gallery Pro - Error Log Disclosure |
| 311 | medium | `opcache-status-exposure` | `/opcache-status/` | OPcache Status Page - Detect |
| 312 | medium | `opencart-error-log` | `/system/storage/logs/error.log` | OpenCart Error Log Disclosure |
| 313 | medium | `opennms-dashboard-exposure` | `/opennms/index.jsp` | OpenNMS Dashboard - Exposure Detection |
| 314 | medium | `oracle-cgi-printenv` | `/cgi-bin/printenv` | Oracle CGI printenv - Information Disclosure |
| 315 | medium | `oracle-ebs-sqllog-exposure` | `/html/bin/sqlnet.log` | Oracle EBS SQL Log - Exposure |
| 316 | medium | `perfsonar-toolkit` | `/toolkit/` | perfSONAR Toolkit - Exposure |
| 317 | medium | `pghero-dashboard-exposure` | `/connections` | PgHero Dashboard Exposure Panel - Detect |
| 318 | medium | `phinx-config` | `/phinx.yml` | Phinx Configuration Exposure |
| 319 | medium | `php-user-ini-disclosure` | `/user.ini` | Php User.ini Disclosure |
| 320 | medium | `plesk-stat` | `/plesk-stat/` | Webalizer Log Analyzer Configuration - Detect |
| 321 | medium | `prisma-schema-exposure` | `/schema.prisma` | Exposed Prisma Database Schema - Exposure |
| 322 | medium | `prometheus-metrics` | `/metrics` | Prometheus Metrics Exposed |
| 323 | medium | `prometheus-metrics` | `/metrics` | Prometheus Metrics - Detect |
| 324 | medium | `prometheus-promtail` | `/service-discovery` | Prometheus Promtail - Exposure |
| 325 | medium | `putty-private-key-disclosure` | `/my.ppk` | Putty Private Key Disclosure |
| 326 | medium | `pyramid-debug-toolbar` | `/_debug_toolbar/` | Pyramid Debug Toolbar |
| 327 | medium | `rails-secret-token-disclosure` | `/config/initializers/secret_token.rb` | Ruby on Rails Secret Token Disclosure |
| 328 | medium | `redis-config` | `/redis.conf` | Redis Configuration File - Detect |
| 329 | medium | `redmine-issues-exposure` | `/issues.json` | Redmine Issues - Exposure |
| 330 | medium | `redpanda-console` | `/overview` | Redpanda Console - Exposure |
| 331 | medium | `secret-token-rb` | `/secret_token.rb` | Secret Token Ruby - File Disclosure |
| 332 | medium | `sensitive-storage-data-expose` | `/storage/` | Sensitive Storage Data - Detect |
| 333 | medium | `service-account-credentials` | `/assets/other/service-account-credentials.json` | Service Account Credentials File Disclosure |
| 334 | medium | `slurm-hpc-dashboard` | `/slurm/` | Slurm HPC Dashboard - Detect |
| 335 | medium | `sonarqube` | `/api/system/status` | SonarQube Exposed |
| 336 | medium | `sonarqube-projects-disclosure` | `/api/components/search_projects` | SonarQube - Information Disclosure |
| 337 | medium | `sound4-directory-listing` | `/log/` | SOUND4 Impact/Pulse/First/Eco <=2.x - Information Disclosure |
| 338 | medium | `springboot-gateway` | `/gateway/routes` | Detect Spring Gateway Actuator |
| 339 | medium | `ssh-authorized-keys` | `/.ssh/authorized_keys` | SSH Authorized Keys File - Detect |
| 340 | medium | `svn-wc-db` | `/.svn/wc.db` | SVN wc.db File Exposure |
| 341 | medium | `swagger-spec` | `/swagger.json` | Swagger/OpenAPI Spec Exposed |
| 342 | medium | `tcpconfig` | `/tcpconfig.html` | Rockwell Automation TCP/IP Configuration Information - Detect |
| 343 | medium | `teampass-ldap` | `/files/ldap.debug.txt` | Teampass LDAP Debug Config - Detect |
| 344 | medium | `teslamate-unauth-access` | `/settings` | TeslaMate - Unauthenticated Access |
| 345 | medium | `transmission-dashboard` | `/transmission/web/` | Transmission Dashboard - Detect |
| 346 | medium | `unauth-fastvue-dashboard` | `/dashboard.aspx` | Fastvue Dashboard Panel - Unauthenticated Detect |
| 347 | medium | `unauthenticated-duplicator-disclosure` | `/wp-content/backups-dup-lite/tmp/` | WordPress Duplicator Plugin - Information disclosure |
| 348 | medium | `untangle-admin-setup` | `/setup/setup.do` | Untangle Exposed Admin Signup |
| 349 | medium | `vercel-source-exposure` | `/_src` | Vercel Source Code Exposure |
| 350 | medium | `wordfence-config-disclosure` | `/wp-content/wflogs/config.php` | WordPress Wordfence - Configuration File Disclosure |
| 351 | medium | `wordfence-rules-disclosure` | `/wp-content/wflogs/rules.php` | WordPress Wordfence - Rules File Disclosure |
| 352 | medium | `wp-user-enum` | `/wp-json/wp/v2/users` | WordPress User Enumeration |
| 353 | medium | `xprober-service` | `/xprober.php` | X Prober Server - Information Disclosure |
| 354 | medium | `zabbix-dashboards-access` | `/zabbix/zabbix.php?action=dashboard.list` | zabbix-dashboards-access |
| 355 | medium | `zen-cart-log-exposure` | `/logs/` | Zen Cart Log File Exposure |
| 356 | low | `3cx-config` | `/SetupConfig.xml` | 3CX Config - File Disclosure |
| 357 | low | `aem-osgi-bundles` | `/bin.tidy.infinity.json` | Adobe AEM Installed OSGI Bundles |
| 358 | low | `airflow-debug` | `/admin/airflow/login` | Airflow Debug Trace |
| 359 | low | `codeception-config` | `/codeception.yml` | Codeception YAML Configuration File - Detect |
| 360 | low | `database-credentials` | `/database_credentials.inc` | Database Credentials File Exposure |
| 361 | low | `debug-vars` | `/debug/vars` | Golang Expvar - Detect |
| 362 | low | `dlink-unauth-cgi-script` | `/cgi-bin/info.cgi` | D-Link DNS Series  CGI Script - Unauthenticated |
| 363 | low | `domcfg-page` | `/domcfg.nsf` | Lotus Domino Configuration Page |
| 364 | low | `drupal-directory-listing` | `/sites/` | Drupal Directory Listing |
| 365 | low | `editor-exposure` | `/.editorconfig` | Editor Configuration File - Detect |
| 366 | low | `elasticsearch` | `/_cluster/health?pretty` | ElasticSearch Information Disclosure |
| 367 | low | `exposed-bitkeeper` | `/BitKeeper/etc/config` | BitKeeper Configuration - Detect |
| 368 | low | `firebase-debug-log` | `/firebase-debug.log` | Firebase Debug Log File Exposure |
| 369 | low | `firebase-detect` | `/.settings/rules.json?auth=FIREBASE_SECRET` | firebase detect |
| 370 | low | `go-pprof-debug` | `/debug/pprof/heap?debug=1` | Go pprof Debug Page |
| 371 | low | `imageresizer-debug-exposure` | `/resizer.debug.ashx` | ImageResizer Debug - Information Exposure |
| 372 | low | `intelbras-dvr-unauth` | `/cap.js` | Intelbras DVR - Unrestricted Access |
| 373 | low | `javascript-env` | `/env.js` | JavaScript Environment Configuration - Detect |
| 374 | low | `jfrog-artifactory-exposure` | `/artifactory/api/repositories` | JFrog Artifactory Artifacts Exposure |
| 375 | low | `joomla-config-dist-file` | `/configuration.php-dist` | Joomla! Configuration File - Detect |
| 376 | low | `joomla-fpd` | `/administrator/manifests/files/joomla.xml` | Joomla! - Full Path Disclosure |
| 377 | low | `keycloak-admin-console-config` | `/admin/master/console/config` | Keycloak Admin Console Configuration Disclosure |
| 378 | low | `librechat-config-exposure` | `/api/config` | librechat - Config Exposure |
| 379 | low | `ms-front-page-misconfig` | `/_vti_inf.html` | Microsoft FrontPage Configuration - Exposure |
| 380 | low | `npm-debug-log` | `/npm-debug.log` | NPM Debug Log Disclosure |
| 381 | low | `oauth-credentials-json` | `/oauth-credentials.json` | Oauth Credentials Json |
| 382 | low | `openstack-config` | `/info` | Openstack - Infomation Disclosure |
| 383 | low | `platformio-ini` | `/platformio.ini` | Platformio Config File Disclosure |
| 384 | low | `prometheus-log` | `/prometheus` | Exposed Prometheus |
| 385 | low | `protractor-config` | `/protractor.conf.js` | Protractor Configuration Exposure |
| 386 | low | `psalm-config` | `/psalm.xml` | Psalm Configuration Exposure - Detect |
| 387 | low | `python-setup-config` | `/setup.py` | Python Setup Configuration - Exposure |
| 388 | low | `ruijie-phpinfo` | `/tool/view/phpinfo.view.php` | Ruijie Phpinfo Configuration - Detect |
| 389 | low | `shell-history` | `/.bash_history` | Shell History |
| 390 | low | `sitecore-debug-page` | `/sitecore/'` | SiteCore Debug Page |
| 391 | low | `sonarqube-public-projects` | `/api/components/suggestions?recentlyBrowsed=` | Sonarqube with public projects |
| 392 | low | `springboot-autoconfig` | `/autoconfig` | Detect Springboot autoconfig Actuator |
| 393 | low | `springboot-beans` | `/beans` | Detect Springboot Beans Actuator |
| 394 | low | `springboot-caches` | `/caches` | Springboot Actuator Caches |
| 395 | low | `springboot-conditions` | `/conditions` | Detect Springboot Conditions Actuator |
| 396 | low | `springboot-configprops` | `/configprops` | Detect Springboot Configprops Actuator |
| 397 | low | `springboot-dump` | `/dump` | Detect Springboot Dump Actuator |
| 398 | low | `springboot-env` | `/env` | Springboot Env Actuator - Detect |
| 399 | low | `springboot-features` | `/features` | Detects Springboot Features Actuator |
| 400 | low | `springboot-flyway` | `/flyway` | Springboot Flyway API |
| 401 | low | `springboot-httpexchanges` | `/httpexchanges` | Detects Springboot HTTP Exchanges Actuator |
| 402 | low | `springboot-httptrace` | `/httptrace` | Detect Springboot httptrace |
| 403 | low | `springboot-integrationgraph` | `/integrationgraph` | Springboot Actuator integrationgraph |
| 404 | low | `springboot-jolokia` | `/jolokia` | Detects Springboot Jolokia Actuator |
| 405 | low | `springboot-liquidbase` | `/liquibase` | Springboot Liquidbase API |
| 406 | low | `springboot-logfile` | `/logfile` | Detects Springboot Logfile Actuator |
| 407 | low | `springboot-loggers` | `/loggers` | Springboot Loggers - Exposure |
| 408 | low | `springboot-sbom` | `/sbom` | Spring Boot Actuator SBOM - Exposure |
| 409 | low | `springboot-startup` | `/startup` | Springboot Actuator startup |
| 410 | low | `springboot-threaddump` | `/threaddump` | Detect Springboot Thread Dump page |
| 411 | low | `token-json` | `/token.json` | Token Json File Disclosure |
| 412 | low | `tomcat-cookie-exposed` | `/examples/servlets/servlet/CookieExample` | Tomcat Cookie Exposed |
| 413 | low | `umbraco-miniprofiler-exposure` | `/mini-profiler-resources/results` | Umbraco Mini Profiler - Exposure |
| 414 | low | `unauthenticated-nginx-dashboard` | `/dashboard.html` | Nginx Dashboard |
| 415 | low | `victoriametrics-vmagent-api-exposure` | `/api/v1/targets` | VictoriaMetrics vmagent - Unauthenticated Targets Exposure |
| 416 | low | `vscode-mcp-json` | `/mcp.json` | Visual Studio Code MCP Configuration ("mcp.json") Exposure |
| 417 | low | `wordpress-wp-env-exposure` | `/.wp-env.json` | WordPress Configuration wp-env - Exposure |
| 418 | low | `yii-debugger` | `/debug/default/view.html` | View Yii Debugger Information |

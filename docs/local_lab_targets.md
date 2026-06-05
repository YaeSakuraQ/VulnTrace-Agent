# 本地靶机启动清单

本清单用于配合 VulnTrace Agent 在本地授权环境中测试功能闭环。

## 使用前提

- 已安装 Docker 与 Docker Compose 插件。
- 建议先执行 `docker version` 与 `docker compose version`，确认本机容器环境可用。
- 所有靶机仅限本地或课程授权环境使用，禁止对公网或未授权目标进行测试。

## DVWA

- 目录：`labs/DVWA`
- 启动：`cd labs/DVWA && docker compose up -d`
- 访问地址：`http://127.0.0.1:4280`
- 首次初始化：访问 `http://127.0.0.1:4280/setup.php`，点击 `Create / Reset Database`
- 默认账号：`admin / password`
- 建议在演示前把安全级别切换为 `low`
- 停止并清理：`cd labs/DVWA && docker compose down -v`

## Vulhub

- 仓库内当前可直接启动的 Vulhub 场景数量：`328`
- 通用启动方法：进入对应场景目录后执行 `docker compose up -d`
- 通用停止方法：进入对应场景目录后执行 `docker compose down -v`
- 通用查看端口方法：进入对应场景目录后执行 `docker compose ps`
- 说明：不同场景暴露端口不同，建议同时查看场景目录内的 `README.md` 或 `README.zh-cn.md`


### 1panel

- `CVE-2024-39907`：`cd labs/vulhub/1panel/CVE-2024-39907 && docker compose up -d`

### activemq

- `CVE-2015-5254`：`cd labs/vulhub/activemq/CVE-2015-5254 && docker compose up -d`
- `CVE-2016-3088`：`cd labs/vulhub/activemq/CVE-2016-3088 && docker compose up -d`
- `CVE-2022-41678`：`cd labs/vulhub/activemq/CVE-2022-41678 && docker compose up -d`
- `CVE-2023-46604`：`cd labs/vulhub/activemq/CVE-2023-46604 && docker compose up -d`
- `CVE-2024-32114`：`cd labs/vulhub/activemq/CVE-2024-32114 && docker compose up -d`
- `CVE-2026-34197`：`cd labs/vulhub/activemq/CVE-2026-34197 && docker compose up -d`

### adminer

- `CVE-2021-21311`：`cd labs/vulhub/adminer/CVE-2021-21311 && docker compose up -d`
- `CVE-2021-43008`：`cd labs/vulhub/adminer/CVE-2021-43008 && docker compose up -d`

### airflow

- `CVE-2020-11978`：`cd labs/vulhub/airflow/CVE-2020-11978 && docker compose up -d`
- `CVE-2020-11981`：`cd labs/vulhub/airflow/CVE-2020-11981 && docker compose up -d`
- `CVE-2020-17526`：`cd labs/vulhub/airflow/CVE-2020-17526 && docker compose up -d`

### aj-report

- `CNVD-2024-15077`：`cd labs/vulhub/aj-report/CNVD-2024-15077 && docker compose up -d`

### apache-cxf

- `CVE-2024-28752`：`cd labs/vulhub/apache-cxf/CVE-2024-28752 && docker compose up -d`

### apache-druid

- `CVE-2021-25646`：`cd labs/vulhub/apache-druid/CVE-2021-25646 && docker compose up -d`

### apereo-cas

- `4.1-rce`：`cd labs/vulhub/apereo-cas/4.1-rce && docker compose up -d`

### apisix

- `CVE-2020-13945`：`cd labs/vulhub/apisix/CVE-2020-13945 && docker compose up -d`
- `CVE-2021-45232`：`cd labs/vulhub/apisix/CVE-2021-45232 && docker compose up -d`

### appweb

- `CVE-2018-8715`：`cd labs/vulhub/appweb/CVE-2018-8715 && docker compose up -d`

### aria2

- `rce`：`cd labs/vulhub/aria2/rce && docker compose up -d`

### bash

- `CVE-2014-6271`：`cd labs/vulhub/bash/CVE-2014-6271 && docker compose up -d`

### budibase

- `CVE-2026-31816`：`cd labs/vulhub/budibase/CVE-2026-31816 && docker compose up -d`

### cacti

- `CVE-2022-46169`：`cd labs/vulhub/cacti/CVE-2022-46169 && docker compose up -d`
- `CVE-2023-39361`：`cd labs/vulhub/cacti/CVE-2023-39361 && docker compose up -d`
- `CVE-2025-24367`：`cd labs/vulhub/cacti/CVE-2025-24367 && docker compose up -d`

### celery

- `celery3_redis_unauth`：`cd labs/vulhub/celery/celery3_redis_unauth && docker compose up -d`

### cgi

- `CVE-2016-5385`：`cd labs/vulhub/cgi/CVE-2016-5385 && docker compose up -d`

### chartbrew

- `CVE-2026-25887`：`cd labs/vulhub/chartbrew/CVE-2026-25887 && docker compose up -d`

### cmsms

- `CVE-2019-9053`：`cd labs/vulhub/cmsms/CVE-2019-9053 && docker compose up -d`
- `CVE-2021-26120`：`cd labs/vulhub/cmsms/CVE-2021-26120 && docker compose up -d`

### coldfusion

- `CVE-2010-2861`：`cd labs/vulhub/coldfusion/CVE-2010-2861 && docker compose up -d`
- `CVE-2017-3066`：`cd labs/vulhub/coldfusion/CVE-2017-3066 && docker compose up -d`
- `CVE-2023-26360`：`cd labs/vulhub/coldfusion/CVE-2023-26360 && docker compose up -d`
- `CVE-2023-29300`：`cd labs/vulhub/coldfusion/CVE-2023-29300 && docker compose up -d`

### comfyui

- `CVE-2025-67303`：`cd labs/vulhub/comfyui/CVE-2025-67303 && docker compose up -d`
- `CVE-2026-22777`：`cd labs/vulhub/comfyui/CVE-2026-22777 && docker compose up -d`

### confluence

- `CVE-2019-3396`：`cd labs/vulhub/confluence/CVE-2019-3396 && docker compose up -d`
- `CVE-2021-26084`：`cd labs/vulhub/confluence/CVE-2021-26084 && docker compose up -d`
- `CVE-2022-26134`：`cd labs/vulhub/confluence/CVE-2022-26134 && docker compose up -d`
- `CVE-2023-22515`：`cd labs/vulhub/confluence/CVE-2023-22515 && docker compose up -d`
- `CVE-2023-22527`：`cd labs/vulhub/confluence/CVE-2023-22527 && docker compose up -d`

### couchdb

- `CVE-2017-12635`：`cd labs/vulhub/couchdb/CVE-2017-12635 && docker compose up -d`
- `CVE-2017-12636`：`cd labs/vulhub/couchdb/CVE-2017-12636 && docker compose up -d`
- `CVE-2022-24706`：`cd labs/vulhub/couchdb/CVE-2022-24706 && docker compose up -d`

### craftcms

- `CVE-2023-41892`：`cd labs/vulhub/craftcms/CVE-2023-41892 && docker compose up -d`
- `CVE-2024-56145`：`cd labs/vulhub/craftcms/CVE-2024-56145 && docker compose up -d`
- `CVE-2025-32432`：`cd labs/vulhub/craftcms/CVE-2025-32432 && docker compose up -d`

### cups-browsed

- `CVE-2024-47177`：`cd labs/vulhub/cups-browsed/CVE-2024-47177 && docker compose up -d`

### dataease

- `CVE-2024-56511`：`cd labs/vulhub/dataease/CVE-2024-56511 && docker compose up -d`
- `CVE-2025-32966`：`cd labs/vulhub/dataease/CVE-2025-32966 && docker compose up -d`
- `CVE-2025-49001`：`cd labs/vulhub/dataease/CVE-2025-49001 && docker compose up -d`

### discuz

- `wooyun-2010-080723`：`cd labs/vulhub/discuz/wooyun-2010-080723 && docker compose up -d`
- `x3.4-arbitrary-file-deletion`：`cd labs/vulhub/discuz/x3.4-arbitrary-file-deletion && docker compose up -d`

### django

- `CVE-2017-12794`：`cd labs/vulhub/django/CVE-2017-12794 && docker compose up -d`
- `CVE-2018-14574`：`cd labs/vulhub/django/CVE-2018-14574 && docker compose up -d`
- `CVE-2019-14234`：`cd labs/vulhub/django/CVE-2019-14234 && docker compose up -d`
- `CVE-2020-9402`：`cd labs/vulhub/django/CVE-2020-9402 && docker compose up -d`
- `CVE-2021-35042`：`cd labs/vulhub/django/CVE-2021-35042 && docker compose up -d`
- `CVE-2022-34265`：`cd labs/vulhub/django/CVE-2022-34265 && docker compose up -d`

### dns

- `dns-zone-transfer`：`cd labs/vulhub/dns/dns-zone-transfer && docker compose up -d`

### docker

- `unauthorized-rce`：`cd labs/vulhub/docker/unauthorized-rce && docker compose up -d`

### drupal

- `CVE-2014-3704`：`cd labs/vulhub/drupal/CVE-2014-3704 && docker compose up -d`
- `CVE-2017-6920`：`cd labs/vulhub/drupal/CVE-2017-6920 && docker compose up -d`
- `CVE-2018-7600`：`cd labs/vulhub/drupal/CVE-2018-7600 && docker compose up -d`
- `CVE-2018-7602`：`cd labs/vulhub/drupal/CVE-2018-7602 && docker compose up -d`
- `CVE-2019-6339`：`cd labs/vulhub/drupal/CVE-2019-6339 && docker compose up -d`
- `CVE-2019-6341`：`cd labs/vulhub/drupal/CVE-2019-6341 && docker compose up -d`

### dubbo

- `CVE-2019-17564`：`cd labs/vulhub/dubbo/CVE-2019-17564 && docker compose up -d`

### ecshop

- `collection_list-sqli`：`cd labs/vulhub/ecshop/collection_list-sqli && docker compose up -d`
- `xianzhi-2017-02-82239600`：`cd labs/vulhub/ecshop/xianzhi-2017-02-82239600 && docker compose up -d`

### elasticsearch

- `CVE-2014-3120`：`cd labs/vulhub/elasticsearch/CVE-2014-3120 && docker compose up -d`
- `CVE-2015-1427`：`cd labs/vulhub/elasticsearch/CVE-2015-1427 && docker compose up -d`
- `CVE-2015-3337`：`cd labs/vulhub/elasticsearch/CVE-2015-3337 && docker compose up -d`
- `CVE-2015-5531`：`cd labs/vulhub/elasticsearch/CVE-2015-5531 && docker compose up -d`
- `WooYun-2015-110216`：`cd labs/vulhub/elasticsearch/WooYun-2015-110216 && docker compose up -d`

### electron

- `CVE-2018-1000006`：`cd labs/vulhub/electron/CVE-2018-1000006 && docker compose up -d`
- `CVE-2018-15685`：`cd labs/vulhub/electron/CVE-2018-15685 && docker compose up -d`

### elfinder

- `CVE-2021-32682`：`cd labs/vulhub/elfinder/CVE-2021-32682 && docker compose up -d`

### erlang

- `CVE-2025-32433`：`cd labs/vulhub/erlang/CVE-2025-32433 && docker compose up -d`

### fastjson

- `1.2.24-rce`：`cd labs/vulhub/fastjson/1.2.24-rce && docker compose up -d`
- `1.2.47-rce`：`cd labs/vulhub/fastjson/1.2.47-rce && docker compose up -d`

### ffmpeg

- `CVE-2016-1897`：`cd labs/vulhub/ffmpeg/CVE-2016-1897 && docker compose up -d`
- `CVE-2017-9993`：`cd labs/vulhub/ffmpeg/CVE-2017-9993 && docker compose up -d`

### flask

- `ssti`：`cd labs/vulhub/flask/ssti && docker compose up -d`

### flink

- `CVE-2020-17518`：`cd labs/vulhub/flink/CVE-2020-17518 && docker compose up -d`
- `CVE-2020-17519`：`cd labs/vulhub/flink/CVE-2020-17519 && docker compose up -d`

### geoserver

- `CVE-2021-40822`：`cd labs/vulhub/geoserver/CVE-2021-40822 && docker compose up -d`
- `CVE-2022-24816`：`cd labs/vulhub/geoserver/CVE-2022-24816 && docker compose up -d`
- `CVE-2023-25157`：`cd labs/vulhub/geoserver/CVE-2023-25157 && docker compose up -d`
- `CVE-2024-36401`：`cd labs/vulhub/geoserver/CVE-2024-36401 && docker compose up -d`

### ghostscript

- `CVE-2018-16509`：`cd labs/vulhub/ghostscript/CVE-2018-16509 && docker compose up -d`
- `CVE-2018-19475`：`cd labs/vulhub/ghostscript/CVE-2018-19475 && docker compose up -d`
- `CVE-2019-6116`：`cd labs/vulhub/ghostscript/CVE-2019-6116 && docker compose up -d`

### git

- `CVE-2017-8386`：`cd labs/vulhub/git/CVE-2017-8386 && docker compose up -d`

### gitea

- `1.4-rce`：`cd labs/vulhub/gitea/1.4-rce && docker compose up -d`

### gitlab

- `CVE-2016-9086`：`cd labs/vulhub/gitlab/CVE-2016-9086 && docker compose up -d`
- `CVE-2021-22205`：`cd labs/vulhub/gitlab/CVE-2021-22205 && docker compose up -d`

### gitlist

- `CVE-2018-1000533`：`cd labs/vulhub/gitlist/CVE-2018-1000533 && docker compose up -d`

### glassfish

- `CVE-2017-1000028`：`cd labs/vulhub/glassfish/CVE-2017-1000028 && docker compose up -d`

### goahead

- `CVE-2017-17562`：`cd labs/vulhub/goahead/CVE-2017-17562 && docker compose up -d`
- `CVE-2021-42342`：`cd labs/vulhub/goahead/CVE-2021-42342 && docker compose up -d`

### gogs

- `CVE-2018-18925`：`cd labs/vulhub/gogs/CVE-2018-18925 && docker compose up -d`

### gradio

- `CVE-2023-51449`：`cd labs/vulhub/gradio/CVE-2023-51449 && docker compose up -d`
- `CVE-2024-1561`：`cd labs/vulhub/gradio/CVE-2024-1561 && docker compose up -d`

### grafana

- `CVE-2021-43798`：`cd labs/vulhub/grafana/CVE-2021-43798 && docker compose up -d`
- `CVE-2024-9264`：`cd labs/vulhub/grafana/CVE-2024-9264 && docker compose up -d`
- `admin-ssrf`：`cd labs/vulhub/grafana/admin-ssrf && docker compose up -d`

### h2database

- `CVE-2018-10054`：`cd labs/vulhub/h2database/CVE-2018-10054 && docker compose up -d`
- `CVE-2021-42392`：`cd labs/vulhub/h2database/CVE-2021-42392 && docker compose up -d`
- `CVE-2022-23221`：`cd labs/vulhub/h2database/CVE-2022-23221 && docker compose up -d`

### hadoop

- `unauthorized-yarn`：`cd labs/vulhub/hadoop/unauthorized-yarn && docker compose up -d`

### hertzbeat

- `CVE-2024-42323`：`cd labs/vulhub/hertzbeat/CVE-2024-42323 && docker compose up -d`

### httpd

- `CVE-2017-15715`：`cd labs/vulhub/httpd/CVE-2017-15715 && docker compose up -d`
- `CVE-2021-40438`：`cd labs/vulhub/httpd/CVE-2021-40438 && docker compose up -d`
- `CVE-2021-41773`：`cd labs/vulhub/httpd/CVE-2021-41773 && docker compose up -d`
- `CVE-2021-42013`：`cd labs/vulhub/httpd/CVE-2021-42013 && docker compose up -d`
- `apache_parsing_vulnerability`：`cd labs/vulhub/httpd/apache_parsing_vulnerability && docker compose up -d`
- `ssi-rce`：`cd labs/vulhub/httpd/ssi-rce && docker compose up -d`

### hugegraph

- `CVE-2024-27348`：`cd labs/vulhub/hugegraph/CVE-2024-27348 && docker compose up -d`
- `CVE-2024-43441`：`cd labs/vulhub/hugegraph/CVE-2024-43441 && docker compose up -d`

### imagemagick

- `CVE-2016-3714`：`cd labs/vulhub/imagemagick/CVE-2016-3714 && docker compose up -d`
- `CVE-2020-29599`：`cd labs/vulhub/imagemagick/CVE-2020-29599 && docker compose up -d`
- `CVE-2022-44268`：`cd labs/vulhub/imagemagick/CVE-2022-44268 && docker compose up -d`

### inetutils

- `CVE-2026-24061`：`cd labs/vulhub/inetutils/CVE-2026-24061 && docker compose up -d`

### influxdb

- `CVE-2019-20933`：`cd labs/vulhub/influxdb/CVE-2019-20933 && docker compose up -d`

### ingress-nginx

- `CVE-2025-1974`：`cd labs/vulhub/ingress-nginx/CVE-2025-1974 && docker compose up -d`

### jackson

- `CVE-2017-7525`：`cd labs/vulhub/jackson/CVE-2017-7525 && docker compose up -d`

### java

- `rmi-codebase`：`cd labs/vulhub/java/rmi-codebase && docker compose up -d`
- `rmi-registry-bind-deserialization-bypass`：`cd labs/vulhub/java/rmi-registry-bind-deserialization-bypass && docker compose up -d`
- `rmi-registry-bind-deserialization`：`cd labs/vulhub/java/rmi-registry-bind-deserialization && docker compose up -d`

### jboss

- `CVE-2017-12149`：`cd labs/vulhub/jboss/CVE-2017-12149 && docker compose up -d`
- `CVE-2017-7504`：`cd labs/vulhub/jboss/CVE-2017-7504 && docker compose up -d`
- `JMXInvokerServlet-deserialization`：`cd labs/vulhub/jboss/JMXInvokerServlet-deserialization && docker compose up -d`

### jenkins

- `CVE-2017-1000353`：`cd labs/vulhub/jenkins/CVE-2017-1000353 && docker compose up -d`
- `CVE-2018-1000861`：`cd labs/vulhub/jenkins/CVE-2018-1000861 && docker compose up -d`
- `CVE-2024-23897`：`cd labs/vulhub/jenkins/CVE-2024-23897 && docker compose up -d`

### jetty

- `CVE-2021-28164`：`cd labs/vulhub/jetty/CVE-2021-28164 && docker compose up -d`
- `CVE-2021-28169`：`cd labs/vulhub/jetty/CVE-2021-28169 && docker compose up -d`
- `CVE-2021-34429`：`cd labs/vulhub/jetty/CVE-2021-34429 && docker compose up -d`

### jimureport

- `CVE-2023-4450`：`cd labs/vulhub/jimureport/CVE-2023-4450 && docker compose up -d`

### jira

- `CVE-2019-11581`：`cd labs/vulhub/jira/CVE-2019-11581 && docker compose up -d`

### jmeter

- `CVE-2018-1297`：`cd labs/vulhub/jmeter/CVE-2018-1297 && docker compose up -d`

### joomla

- `CVE-2015-8562`：`cd labs/vulhub/joomla/CVE-2015-8562 && docker compose up -d`
- `CVE-2017-8917`：`cd labs/vulhub/joomla/CVE-2017-8917 && docker compose up -d`
- `CVE-2023-23752`：`cd labs/vulhub/joomla/CVE-2023-23752 && docker compose up -d`

### jumpserver

- `CVE-2023-42820`：`cd labs/vulhub/jumpserver/CVE-2023-42820 && docker compose up -d`

### jupyter

- `notebook-rce`：`cd labs/vulhub/jupyter/notebook-rce && docker compose up -d`

### kafka

- `CVE-2023-25194`：`cd labs/vulhub/kafka/CVE-2023-25194 && docker compose up -d`

### kibana

- `CVE-2018-17246`：`cd labs/vulhub/kibana/CVE-2018-17246 && docker compose up -d`
- `CVE-2019-7609`：`cd labs/vulhub/kibana/CVE-2019-7609 && docker compose up -d`
- `CVE-2020-7012`：`cd labs/vulhub/kibana/CVE-2020-7012 && docker compose up -d`

### kkfileview

- `4.3-zipslip-rce`：`cd labs/vulhub/kkfileview/4.3-zipslip-rce && docker compose up -d`

### langflow

- `CVE-2025-3248`：`cd labs/vulhub/langflow/CVE-2025-3248 && docker compose up -d`

### laravel

- `CVE-2021-3129`：`cd labs/vulhub/laravel/CVE-2021-3129 && docker compose up -d`

### librsvg

- `CVE-2023-38633`：`cd labs/vulhub/librsvg/CVE-2023-38633 && docker compose up -d`

### libssh

- `CVE-2018-10933`：`cd labs/vulhub/libssh/CVE-2018-10933 && docker compose up -d`

### liferay-portal

- `CVE-2020-7961`：`cd labs/vulhub/liferay-portal/CVE-2020-7961 && docker compose up -d`

### linkis

- `CVE-2022-44645`：`cd labs/vulhub/linkis/CVE-2022-44645 && docker compose up -d`

### livewire

- `CVE-2025-54068`：`cd labs/vulhub/livewire/CVE-2025-54068 && docker compose up -d`

### log4j

- `CVE-2017-5645`：`cd labs/vulhub/log4j/CVE-2017-5645 && docker compose up -d`
- `CVE-2021-44228`：`cd labs/vulhub/log4j/CVE-2021-44228 && docker compose up -d`

### magento

- `2.2-sqli`：`cd labs/vulhub/magento/2.2-sqli && docker compose up -d`

### metabase

- `CVE-2021-41277`：`cd labs/vulhub/metabase/CVE-2021-41277 && docker compose up -d`
- `CVE-2023-38646`：`cd labs/vulhub/metabase/CVE-2023-38646 && docker compose up -d`

### metersphere

- `CVE-2021-45788`：`cd labs/vulhub/metersphere/CVE-2021-45788 && docker compose up -d`
- `plugin-rce`：`cd labs/vulhub/metersphere/plugin-rce && docker compose up -d`

### mini_httpd

- `CVE-2018-18778`：`cd labs/vulhub/mini_httpd/CVE-2018-18778 && docker compose up -d`

### minio

- `CVE-2023-28432`：`cd labs/vulhub/minio/CVE-2023-28432 && docker compose up -d`

### mojarra

- `jsf-viewstate-deserialization`：`cd labs/vulhub/mojarra/jsf-viewstate-deserialization && docker compose up -d`

### mongo-express

- `CVE-2019-10758`：`cd labs/vulhub/mongo-express/CVE-2019-10758 && docker compose up -d`

### mysql

- `CVE-2012-2122`：`cd labs/vulhub/mysql/CVE-2012-2122 && docker compose up -d`

### n8n

- `CVE-2025-68613`：`cd labs/vulhub/n8n/CVE-2025-68613 && docker compose up -d`
- `CVE-2026-21858`：`cd labs/vulhub/n8n/CVE-2026-21858 && docker compose up -d`

### nacos

- `CVE-2021-29441`：`cd labs/vulhub/nacos/CVE-2021-29441 && docker compose up -d`
- `CVE-2021-29442`：`cd labs/vulhub/nacos/CVE-2021-29442 && docker compose up -d`

### neo4j

- `CVE-2021-34371`：`cd labs/vulhub/neo4j/CVE-2021-34371 && docker compose up -d`

### next.js

- `CVE-2025-29927`：`cd labs/vulhub/next.js/CVE-2025-29927 && docker compose up -d`

### nexus

- `CVE-2019-7238`：`cd labs/vulhub/nexus/CVE-2019-7238 && docker compose up -d`
- `CVE-2020-10199`：`cd labs/vulhub/nexus/CVE-2020-10199 && docker compose up -d`
- `CVE-2020-10204`：`cd labs/vulhub/nexus/CVE-2020-10204 && docker compose up -d`
- `CVE-2024-4956`：`cd labs/vulhub/nexus/CVE-2024-4956 && docker compose up -d`

### nginx-ui

- `CVE-2026-27944`：`cd labs/vulhub/nginx-ui/CVE-2026-27944 && docker compose up -d`

### nginx

- `CVE-2013-4547`：`cd labs/vulhub/nginx/CVE-2013-4547 && docker compose up -d`
- `CVE-2017-7529`：`cd labs/vulhub/nginx/CVE-2017-7529 && docker compose up -d`
- `insecure-configuration`：`cd labs/vulhub/nginx/insecure-configuration && docker compose up -d`
- `nginx_parsing_vulnerability`：`cd labs/vulhub/nginx/nginx_parsing_vulnerability && docker compose up -d`

### node

- `CVE-2017-14849`：`cd labs/vulhub/node/CVE-2017-14849 && docker compose up -d`
- `CVE-2017-16082`：`cd labs/vulhub/node/CVE-2017-16082 && docker compose up -d`

### ntopng

- `CVE-2021-28073`：`cd labs/vulhub/ntopng/CVE-2021-28073 && docker compose up -d`

### ofbiz

- `CVE-2020-9496`：`cd labs/vulhub/ofbiz/CVE-2020-9496 && docker compose up -d`
- `CVE-2023-49070`：`cd labs/vulhub/ofbiz/CVE-2023-49070 && docker compose up -d`
- `CVE-2023-51467`：`cd labs/vulhub/ofbiz/CVE-2023-51467 && docker compose up -d`
- `CVE-2024-38856`：`cd labs/vulhub/ofbiz/CVE-2024-38856 && docker compose up -d`
- `CVE-2024-45195`：`cd labs/vulhub/ofbiz/CVE-2024-45195 && docker compose up -d`
- `CVE-2024-45507`：`cd labs/vulhub/ofbiz/CVE-2024-45507 && docker compose up -d`

### openclaw

- `CVE-2026-25253`：`cd labs/vulhub/openclaw/CVE-2026-25253 && docker compose up -d`

### openfire

- `CVE-2023-32315`：`cd labs/vulhub/openfire/CVE-2023-32315 && docker compose up -d`

### opensmtpd

- `CVE-2020-7247`：`cd labs/vulhub/opensmtpd/CVE-2020-7247 && docker compose up -d`

### openssh

- `CVE-2018-15473`：`cd labs/vulhub/openssh/CVE-2018-15473 && docker compose up -d`

### openssl

- `CVE-2014-0160`：`cd labs/vulhub/openssl/CVE-2014-0160 && docker compose up -d`
- `CVE-2022-0778`：`cd labs/vulhub/openssl/CVE-2022-0778 && docker compose up -d`

### opentsdb

- `CVE-2020-35476`：`cd labs/vulhub/opentsdb/CVE-2020-35476 && docker compose up -d`
- `CVE-2023-25826`：`cd labs/vulhub/opentsdb/CVE-2023-25826 && docker compose up -d`

### owncloud

- `CVE-2023-49103`：`cd labs/vulhub/owncloud/CVE-2023-49103 && docker compose up -d`

### pdfjs

- `CVE-2024-4367`：`cd labs/vulhub/pdfjs/CVE-2024-4367 && docker compose up -d`

### pgadmin

- `CVE-2022-4223`：`cd labs/vulhub/pgadmin/CVE-2022-4223 && docker compose up -d`
- `CVE-2023-5002`：`cd labs/vulhub/pgadmin/CVE-2023-5002 && docker compose up -d`
- `CVE-2025-13780`：`cd labs/vulhub/pgadmin/CVE-2025-13780 && docker compose up -d`
- `CVE-2025-2945`：`cd labs/vulhub/pgadmin/CVE-2025-2945 && docker compose up -d`

### php

- `8.1-backdoor`：`cd labs/vulhub/php/8.1-backdoor && docker compose up -d`
- `CVE-2012-1823`：`cd labs/vulhub/php/CVE-2012-1823 && docker compose up -d`
- `CVE-2018-19518`：`cd labs/vulhub/php/CVE-2018-19518 && docker compose up -d`
- `CVE-2019-11043`：`cd labs/vulhub/php/CVE-2019-11043 && docker compose up -d`
- `CVE-2024-2961`：`cd labs/vulhub/php/CVE-2024-2961 && docker compose up -d`
- `fpm`：`cd labs/vulhub/php/fpm && docker compose up -d`
- `inclusion`：`cd labs/vulhub/php/inclusion && docker compose up -d`
- `php_xxe`：`cd labs/vulhub/php/php_xxe && docker compose up -d`
- `xdebug-rce`：`cd labs/vulhub/php/xdebug-rce && docker compose up -d`

### phpmailer

- `CVE-2017-5223`：`cd labs/vulhub/phpmailer/CVE-2017-5223 && docker compose up -d`

### phpmyadmin

- `CVE-2016-5734`：`cd labs/vulhub/phpmyadmin/CVE-2016-5734 && docker compose up -d`
- `CVE-2018-12613`：`cd labs/vulhub/phpmyadmin/CVE-2018-12613 && docker compose up -d`
- `WooYun-2016-199433`：`cd labs/vulhub/phpmyadmin/WooYun-2016-199433 && docker compose up -d`

### phpunit

- `CVE-2017-9841`：`cd labs/vulhub/phpunit/CVE-2017-9841 && docker compose up -d`

### polkit

- `CVE-2021-4034`：`cd labs/vulhub/polkit/CVE-2021-4034 && docker compose up -d`

### postgres

- `CVE-2018-1058`：`cd labs/vulhub/postgres/CVE-2018-1058 && docker compose up -d`
- `CVE-2019-9193`：`cd labs/vulhub/postgres/CVE-2019-9193 && docker compose up -d`

### python

- `CVE-2024-23334`：`cd labs/vulhub/python/CVE-2024-23334 && docker compose up -d`
- `PIL-CVE-2017-8291`：`cd labs/vulhub/python/PIL-CVE-2017-8291 && docker compose up -d`
- `PIL-CVE-2018-16509`：`cd labs/vulhub/python/PIL-CVE-2018-16509 && docker compose up -d`
- `unpickle`：`cd labs/vulhub/python/unpickle && docker compose up -d`

### rails

- `CVE-2018-3760`：`cd labs/vulhub/rails/CVE-2018-3760 && docker compose up -d`
- `CVE-2019-5418`：`cd labs/vulhub/rails/CVE-2019-5418 && docker compose up -d`

### react

- `CVE-2025-55182`：`cd labs/vulhub/react/CVE-2025-55182 && docker compose up -d`

### redis

- `4-unacc`：`cd labs/vulhub/redis/4-unacc && docker compose up -d`
- `CVE-2022-0543`：`cd labs/vulhub/redis/CVE-2022-0543 && docker compose up -d`

### rocketchat

- `CVE-2021-22911`：`cd labs/vulhub/rocketchat/CVE-2021-22911 && docker compose up -d`

### rocketmq

- `CVE-2023-33246`：`cd labs/vulhub/rocketmq/CVE-2023-33246 && docker compose up -d`
- `CVE-2023-37582`：`cd labs/vulhub/rocketmq/CVE-2023-37582 && docker compose up -d`

### rsync

- `common`：`cd labs/vulhub/rsync/common && docker compose up -d`

### ruby

- `CVE-2017-17405`：`cd labs/vulhub/ruby/CVE-2017-17405 && docker compose up -d`

### saltstack

- `CVE-2020-11651`：`cd labs/vulhub/saltstack/CVE-2020-11651 && docker compose up -d`
- `CVE-2020-11652`：`cd labs/vulhub/saltstack/CVE-2020-11652 && docker compose up -d`
- `CVE-2020-16846`：`cd labs/vulhub/saltstack/CVE-2020-16846 && docker compose up -d`

### samba

- `CVE-2017-7494`：`cd labs/vulhub/samba/CVE-2017-7494 && docker compose up -d`

### scrapy

- `scrapyd-unacc`：`cd labs/vulhub/scrapy/scrapyd-unacc && docker compose up -d`

### shiro

- `CVE-2010-3863`：`cd labs/vulhub/shiro/CVE-2010-3863 && docker compose up -d`
- `CVE-2016-4437`：`cd labs/vulhub/shiro/CVE-2016-4437 && docker compose up -d`
- `CVE-2020-1957`：`cd labs/vulhub/shiro/CVE-2020-1957 && docker compose up -d`

### showdoc

- `3.2.5-sqli`：`cd labs/vulhub/showdoc/3.2.5-sqli && docker compose up -d`
- `CNVD-2020-26585`：`cd labs/vulhub/showdoc/CNVD-2020-26585 && docker compose up -d`

### skywalking

- `8.3.0-sqli`：`cd labs/vulhub/skywalking/8.3.0-sqli && docker compose up -d`

### solr

- `CVE-2017-12629-RCE`：`cd labs/vulhub/solr/CVE-2017-12629-RCE && docker compose up -d`
- `CVE-2017-12629-XXE`：`cd labs/vulhub/solr/CVE-2017-12629-XXE && docker compose up -d`
- `CVE-2019-0193`：`cd labs/vulhub/solr/CVE-2019-0193 && docker compose up -d`
- `CVE-2019-17558`：`cd labs/vulhub/solr/CVE-2019-17558 && docker compose up -d`
- `Remote-Streaming-Fileread`：`cd labs/vulhub/solr/Remote-Streaming-Fileread && docker compose up -d`

### spark

- `unacc`：`cd labs/vulhub/spark/unacc && docker compose up -d`

### spring

- `CVE-2016-4977`：`cd labs/vulhub/spring/CVE-2016-4977 && docker compose up -d`
- `CVE-2017-4971`：`cd labs/vulhub/spring/CVE-2017-4971 && docker compose up -d`
- `CVE-2017-8046`：`cd labs/vulhub/spring/CVE-2017-8046 && docker compose up -d`
- `CVE-2018-1270`：`cd labs/vulhub/spring/CVE-2018-1270 && docker compose up -d`
- `CVE-2018-1273`：`cd labs/vulhub/spring/CVE-2018-1273 && docker compose up -d`
- `CVE-2022-22947`：`cd labs/vulhub/spring/CVE-2022-22947 && docker compose up -d`
- `CVE-2022-22963`：`cd labs/vulhub/spring/CVE-2022-22963 && docker compose up -d`
- `CVE-2022-22965`：`cd labs/vulhub/spring/CVE-2022-22965 && docker compose up -d`
- `CVE-2022-22978`：`cd labs/vulhub/spring/CVE-2022-22978 && docker compose up -d`
- `CVE-2025-41242`：`cd labs/vulhub/spring/CVE-2025-41242 && docker compose up -d`

### struts2

- `s2-001`：`cd labs/vulhub/struts2/s2-001 && docker compose up -d`
- `s2-005`：`cd labs/vulhub/struts2/s2-005 && docker compose up -d`
- `s2-007`：`cd labs/vulhub/struts2/s2-007 && docker compose up -d`
- `s2-008`：`cd labs/vulhub/struts2/s2-008 && docker compose up -d`
- `s2-009`：`cd labs/vulhub/struts2/s2-009 && docker compose up -d`
- `s2-012`：`cd labs/vulhub/struts2/s2-012 && docker compose up -d`
- `s2-013`：`cd labs/vulhub/struts2/s2-013 && docker compose up -d`
- `s2-015`：`cd labs/vulhub/struts2/s2-015 && docker compose up -d`
- `s2-016`：`cd labs/vulhub/struts2/s2-016 && docker compose up -d`
- `s2-032`：`cd labs/vulhub/struts2/s2-032 && docker compose up -d`
- `s2-045`：`cd labs/vulhub/struts2/s2-045 && docker compose up -d`
- `s2-046`：`cd labs/vulhub/struts2/s2-046 && docker compose up -d`
- `s2-048`：`cd labs/vulhub/struts2/s2-048 && docker compose up -d`
- `s2-052`：`cd labs/vulhub/struts2/s2-052 && docker compose up -d`
- `s2-053`：`cd labs/vulhub/struts2/s2-053 && docker compose up -d`
- `s2-057`：`cd labs/vulhub/struts2/s2-057 && docker compose up -d`
- `s2-059`：`cd labs/vulhub/struts2/s2-059 && docker compose up -d`
- `s2-061`：`cd labs/vulhub/struts2/s2-061 && docker compose up -d`
- `s2-066`：`cd labs/vulhub/struts2/s2-066 && docker compose up -d`
- `s2-067`：`cd labs/vulhub/struts2/s2-067 && docker compose up -d`

### superset

- `CVE-2023-27524`：`cd labs/vulhub/superset/CVE-2023-27524 && docker compose up -d`
- `CVE-2023-37941`：`cd labs/vulhub/superset/CVE-2023-37941 && docker compose up -d`

### supervisor

- `CVE-2017-11610`：`cd labs/vulhub/supervisor/CVE-2017-11610 && docker compose up -d`

### teamcity

- `CVE-2023-42793`：`cd labs/vulhub/teamcity/CVE-2023-42793 && docker compose up -d`
- `CVE-2024-27198`：`cd labs/vulhub/teamcity/CVE-2024-27198 && docker compose up -d`

### thinkphp

- `2-rce`：`cd labs/vulhub/thinkphp/2-rce && docker compose up -d`
- `5-rce`：`cd labs/vulhub/thinkphp/5-rce && docker compose up -d`
- `5.0.23-rce`：`cd labs/vulhub/thinkphp/5.0.23-rce && docker compose up -d`
- `in-sqlinjection`：`cd labs/vulhub/thinkphp/in-sqlinjection && docker compose up -d`
- `lang-rce`：`cd labs/vulhub/thinkphp/lang-rce && docker compose up -d`

### tikiwiki

- `CVE-2020-15906`：`cd labs/vulhub/tikiwiki/CVE-2020-15906 && docker compose up -d`

### tomcat

- `CVE-2017-12615`：`cd labs/vulhub/tomcat/CVE-2017-12615 && docker compose up -d`
- `CVE-2020-1938`：`cd labs/vulhub/tomcat/CVE-2020-1938 && docker compose up -d`
- `CVE-2025-24813`：`cd labs/vulhub/tomcat/CVE-2025-24813 && docker compose up -d`
- `CVE-2026-34486`：`cd labs/vulhub/tomcat/CVE-2026-34486 && docker compose up -d`
- `tomcat8`：`cd labs/vulhub/tomcat/tomcat8 && docker compose up -d`

### unomi

- `CVE-2020-13942`：`cd labs/vulhub/unomi/CVE-2020-13942 && docker compose up -d`

### uwsgi

- `CVE-2018-7490`：`cd labs/vulhub/uwsgi/CVE-2018-7490 && docker compose up -d`
- `unacc`：`cd labs/vulhub/uwsgi/unacc && docker compose up -d`

### v2board

- `1.6-privilege-escalation`：`cd labs/vulhub/v2board/1.6-privilege-escalation && docker compose up -d`

### vite

- `CNVD-2022-44615`：`cd labs/vulhub/vite/CNVD-2022-44615 && docker compose up -d`
- `CVE-2025-30208`：`cd labs/vulhub/vite/CVE-2025-30208 && docker compose up -d`
- `CVE-2025-32395`：`cd labs/vulhub/vite/CVE-2025-32395 && docker compose up -d`
- `CVE-2026-39363`：`cd labs/vulhub/vite/CVE-2026-39363 && docker compose up -d`

### weblogic

- `CVE-2017-10271`：`cd labs/vulhub/weblogic/CVE-2017-10271 && docker compose up -d`
- `CVE-2018-2628`：`cd labs/vulhub/weblogic/CVE-2018-2628 && docker compose up -d`
- `CVE-2018-2894`：`cd labs/vulhub/weblogic/CVE-2018-2894 && docker compose up -d`
- `CVE-2020-14882`：`cd labs/vulhub/weblogic/CVE-2020-14882 && docker compose up -d`
- `CVE-2023-21839`：`cd labs/vulhub/weblogic/CVE-2023-21839 && docker compose up -d`
- `ssrf`：`cd labs/vulhub/weblogic/ssrf && docker compose up -d`
- `weak_password`：`cd labs/vulhub/weblogic/weak_password && docker compose up -d`

### webmin

- `CVE-2019-15107`：`cd labs/vulhub/webmin/CVE-2019-15107 && docker compose up -d`

### wordpress

- `pwnscriptum`：`cd labs/vulhub/wordpress/pwnscriptum && docker compose up -d`

### xstream

- `CVE-2021-21351`：`cd labs/vulhub/xstream/CVE-2021-21351 && docker compose up -d`
- `CVE-2021-29505`：`cd labs/vulhub/xstream/CVE-2021-29505 && docker compose up -d`

### xxl-job

- `unacc`：`cd labs/vulhub/xxl-job/unacc && docker compose up -d`

### yapi

- `mongodb-inj`：`cd labs/vulhub/yapi/mongodb-inj && docker compose up -d`
- `unacc`：`cd labs/vulhub/yapi/unacc && docker compose up -d`

### zabbix

- `CVE-2016-10134`：`cd labs/vulhub/zabbix/CVE-2016-10134 && docker compose up -d`
- `CVE-2017-2824`：`cd labs/vulhub/zabbix/CVE-2017-2824 && docker compose up -d`
- `CVE-2020-11800`：`cd labs/vulhub/zabbix/CVE-2020-11800 && docker compose up -d`

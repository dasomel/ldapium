{{/*
Expand the name of the chart.
*/}}
{{- define "ldapium.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name. Truncated to 63 chars because
some Kubernetes name fields are limited to that (by the DNS naming spec).
StatefulSet pod ordinals (-0, -1, ...) add further suffix, so the headless
service name (which gets its own "-headless" suffix) is kept well under the
limit.
*/}}
{{- define "ldapium.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Headless service name. */}}
{{- define "ldapium.headlessName" -}}
{{- printf "%s-headless" (include "ldapium.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* UI component fullname. */}}
{{- define "ldapium.ui.fullname" -}}
{{- printf "%s-ui" (include "ldapium.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Chart label value. */}}
{{- define "ldapium.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "ldapium.labels" -}}
helm.sh/chart: {{ include "ldapium.chart" . }}
{{ include "ldapium.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Server selector labels. */}}
{{- define "ldapium.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ldapium.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end -}}

{{/* UI labels / selector labels. */}}
{{- define "ldapium.ui.labels" -}}
helm.sh/chart: {{ include "ldapium.chart" . }}
{{ include "ldapium.ui.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "ldapium.ui.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ldapium.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: ui
{{- end -}}

{{/*
The validated UI metrics port as a plain number. It must be digits only, within
1-65535, and not 8080 (the UI container's own HTTP listener, which METRICS_ADDR
would collide with, so the backend would refuse to start). Compared numerically,
so 08080 is 8080. Included wherever the port is rendered, so a bad value fails
every template that would use it.
*/}}
{{- define "ldapium.ui.metricsPort" -}}
{{- $raw := printf "%v" .Values.ui.metrics.port | trim -}}
{{- if not (regexMatch "^[0-9]+$" $raw) }}{{ fail (printf "ui.metrics.port must be a number in 1-65535, got %q" $raw) }}{{ end -}}
{{- $port := atoi $raw -}}
{{- if or (lt $port 1) (gt $port 65535) }}{{ fail (printf "ui.metrics.port must be in 1-65535, got %q" $raw) }}{{ end -}}
{{- if eq $port 8080 }}{{ fail "ui.metrics.port must not be 8080: that is the UI container's own HTTP listener (the metrics listener would collide with it and the backend would refuse to start)" }}{{ end -}}
{{- $port -}}
{{- end -}}

{{/* Labels of the UI metrics Service. A distinct component keeps it out of the selector of every other Service/ServiceMonitor of this chart. */}}
{{- define "ldapium.ui.metricsLabels" -}}
helm.sh/chart: {{ include "ldapium.chart" . }}
app.kubernetes.io/name: {{ include "ldapium.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: ui-metrics
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Backup labels / selector labels. */}}
{{- define "ldapium.backup.labels" -}}
helm.sh/chart: {{ include "ldapium.chart" . }}
{{ include "ldapium.backup.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "ldapium.backup.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ldapium.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: backup
{{- end -}}

{{/* Server ServiceAccount name. */}}
{{- define "ldapium.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- .Values.serviceAccount.name | default (include "ldapium.fullname" .) -}}
{{- else -}}
{{- .Values.serviceAccount.name | default "default" -}}
{{- end -}}
{{- end -}}

{{/* UI ServiceAccount name. */}}
{{- define "ldapium.ui.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- .Values.serviceAccount.name | default (include "ldapium.ui.fullname" .) -}}
{{- else -}}
{{- .Values.serviceAccount.name | default "default" -}}
{{- end -}}
{{- end -}}

{{/* Admin password Secret name. */}}
{{- define "ldapium.adminSecretName" -}}
{{- .Values.auth.existingSecret | default (printf "%s-admin" (include "ldapium.fullname" .)) -}}
{{- end -}}

{{/* Server image reference. */}}
{{- define "ldapium.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.Version) -}}
{{- end -}}

{{/* UI image reference. */}}
{{- define "ldapium.ui.image" -}}
{{- printf "%s:%s" .Values.ui.image.repository (.Values.ui.image.tag | default .Chart.Version) -}}
{{- end -}}

{{/*
Whether replication is enabled: explicit override wins; otherwise auto-enable
when replicaCount > 1.
*/}}
{{- define "ldapium.replicationEnabled" -}}
{{- if hasKey .Values.replication "enabled" -}}
{{- .Values.replication.enabled -}}
{{- else -}}
{{- gt (int .Values.replicaCount) 1 -}}
{{- end -}}
{{- end -}}

{{/*
Comma-separated replication peer URLs in ordinal order. When server TLS is
enabled, replication is also forced over LDAPS so the chart cannot advertise
TLS for clients while silently using plaintext for syncrepl.
*/}}
{{- define "ldapium.replicationPeers" -}}
{{- $fullname := include "ldapium.fullname" . -}}
{{- $headless := include "ldapium.headlessName" . -}}
{{- $ns := .Release.Namespace -}}
{{- $domain := .Values.replication.clusterDomain -}}
{{- $count := int .Values.replicaCount -}}
{{- $scheme := "ldap" -}}
{{- $port := 389 -}}
{{- if .Values.tls.enabled -}}
{{- $scheme = "ldaps" -}}
{{- $port = 636 -}}
{{- end -}}
{{- $peers := list -}}
{{- range $i := until $count -}}
{{- $peers = append $peers (printf "%s://%s-%d.%s.%s.svc.%s:%d" $scheme $fullname $i $headless $ns $domain $port) -}}
{{- end -}}
{{- join "," $peers -}}
{{- end -}}

{{/* Data volume size in bytes for LDAP_DB_MAX_SIZE. */}}
{{- define "ldapium.dataVolumeBytes" -}}
{{- $s := .Values.persistence.data.size | toString -}}
{{- if regexMatch "^[0-9]+Ti$" $s -}}
{{- mul (trimSuffix "Ti" $s | int64) 1099511627776 -}}
{{- else if regexMatch "^[0-9]+Gi$" $s -}}
{{- mul (trimSuffix "Gi" $s | int64) 1073741824 -}}
{{- else if regexMatch "^[0-9]+Mi$" $s -}}
{{- mul (trimSuffix "Mi" $s | int64) 1048576 -}}
{{- else if regexMatch "^[0-9]+Ki$" $s -}}
{{- mul (trimSuffix "Ki" $s | int64) 1024 -}}
{{- else if regexMatch "^[0-9]+$" $s -}}
{{- $s -}}
{{- else -}}
{{- fail (printf "persistence.data.size %q is not a plain byte count or a Ki/Mi/Gi/Ti quantity; set ldap.dbMaxSize explicitly (in bytes) if you need another form" $s) -}}
{{- end -}}
{{- end -}}

{{/*
Refuse hardening combinations that would silently break the deployment.
Rendered from statefulset.yaml, so every `helm template`/`install` runs it.
*/}}
{{- define "ldapium.validateHardening" -}}
{{- $h := .Values.ldap.hardening -}}
{{/* D66: mode selects the identity and credential atomically. Admin rollback cannot
retain a dedicated password and silently stall the administrator bind. */}}
{{- if eq .Values.replication.identity "dedicated" -}}
{{- if ne (include "ldapium.replicationEnabled" .) "true" -}}
{{- fail "replication.identity=dedicated requires replication enabled" -}}
{{- end -}}
{{- if or (not .Values.tls.enabled) (not .Values.tls.caFile) (not .Values.tls.existingSecret) -}}
{{- fail "replication.identity=dedicated requires tls.enabled, tls.caFile and tls.existingSecret for verified TLS" -}}
{{- end -}}
{{- if or (not .Values.replication.existingSecret) .Values.replication.bindDN -}}
{{- fail "replication.identity=dedicated requires replication.existingSecret and an empty replication.bindDN (the image selects the reserved DN)" -}}
{{- end -}}
{{- else if .Values.replication.existingSecret -}}
{{- fail "replication.existingSecret is dedicated-only; remove it when rolling back identity to admin/prepare" -}}
{{- end -}}

{{- if and (or $h.disallowAnonBind $h.requireAuthc) .Values.ldap.anonymousReadBase -}}
{{- fail "ldap.hardening.disallowAnonBind / requireAuthc contradict ldap.anonymousReadBase: anonymous uid lookups (SSSD, Keycloak federation, the UI's bare-uid login) would be rejected. Unset ldap.anonymousReadBase and move those clients to a bind DN, or leave both hardening flags false." -}}
{{- end -}}
{{- if and (or $h.disallowAnonBind $h.requireAuthc) .Values.ui.enabled .Values.ui.ldap.userSearchFilter -}}
{{- fail "ldap.hardening.disallowAnonBind / requireAuthc break the UI's bare-uid login: ui.ldap.userSearchFilter resolves uid to DN with an ANONYMOUS search, which the server would now reject. Set ui.ldap.userSearchFilter=\"\" (users log in with their full DN), disable ui.enabled, or leave both hardening flags false." -}}
{{- end -}}
{{- if and $h.requireTls (not .Values.tls.enabled) -}}
{{- fail "ldap.hardening.requireTls requires tls.enabled=true (and tls.existingSecret); otherwise no client could connect at all." -}}
{{- end -}}
{{- if and $h.requireTls .Values.metrics .Values.metrics.enabled -}}
{{- fail "ldap.hardening.requireTls conflicts with metrics.enabled: the exporter sidecar binds over plaintext ldap://127.0.0.1:389 and would be refused. Disable metrics or leave requireTls false." -}}
{{- end -}}
{{- if and $h.requireTls .Values.ui.enabled .Values.ui.ldap.url (hasPrefix "ldap://" .Values.ui.ldap.url) (not .Values.ui.ldap.startTLS) -}}
{{- fail "ldap.hardening.requireTls with ui.ldap.url on plain ldap:// needs ui.ldap.startTLS=true (or an ldaps:// URL); the UI could not bind otherwise." -}}
{{- end -}}
{{- if and .Values.ldap.lastBind.enabled (not .Values.ldap.lastBind.allowWithReplication) (eq (include "ldapium.replicationEnabled" .) "true") -}}
{{- fail "ldap.lastBind.enabled with replication can silently undo a password change or lockout made on another node during a partition (the bind's pwdLastSuccess write carries a newer entryCSN and wins last-write-wins). Keep lastBind disabled on multi-provider deployments, or set ldap.lastBind.allowWithReplication=true to accept that risk." -}}
{{- end -}}
{{- if and .Values.ldap.modules.dynlistEnabled (eq (include "ldapium.replicationEnabled" .) "true") -}}
{{- fail "ldap.modules.dynlistEnabled is not supported with replication: computed dynlist values would enter the syncrepl stream (the image entrypoint refuses to start). Disable dynlistEnabled or replication." -}}
{{- end -}}
{{- end -}}

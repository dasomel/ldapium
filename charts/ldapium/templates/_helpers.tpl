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

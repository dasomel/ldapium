{{/*
Expand the name of the chart.
*/}}
{{- define "openldap.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name. Truncated to 63 chars because
some Kubernetes name fields are limited to that (by the DNS naming spec).
StatefulSet pod ordinals (-0, -1, ...) add further suffix, so the headless
service name (which gets its own "-headless" suffix) is kept well under the
limit.
*/}}
{{- define "openldap.fullname" -}}
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

{{/*
Headless service name (StatefulSet peer discovery).
*/}}
{{- define "openldap.headlessName" -}}
{{- printf "%s-headless" (include "openldap.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
UI component fullname.
*/}}
{{- define "openldap.ui.fullname" -}}
{{- printf "%s-ui" (include "openldap.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "openldap.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "openldap.labels" -}}
helm.sh/chart: {{ include "openldap.chart" . }}
{{ include "openldap.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels (server component).
*/}}
{{- define "openldap.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openldap.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end -}}

{{/*
UI labels / selector labels.
*/}}
{{- define "openldap.ui.labels" -}}
helm.sh/chart: {{ include "openldap.chart" . }}
{{ include "openldap.ui.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "openldap.ui.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openldap.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: ui
{{- end -}}

{{/*
Backup CronJob labels / selector labels. Own component value (not the server
"server" one from openldap.selectorLabels) — separate helper for the same
reason ui.* has its own, rather than emitting the same key twice.
*/}}
{{- define "openldap.backup.labels" -}}
helm.sh/chart: {{ include "openldap.chart" . }}
{{ include "openldap.backup.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "openldap.backup.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openldap.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: backup
{{- end -}}

{{/*
Server ServiceAccount name.
*/}}
{{- define "openldap.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- .Values.serviceAccount.name | default (include "openldap.fullname" .) -}}
{{- else -}}
{{- .Values.serviceAccount.name | default "default" -}}
{{- end -}}
{{- end -}}

{{/*
UI ServiceAccount name (reuses the same create toggle).
*/}}
{{- define "openldap.ui.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- .Values.serviceAccount.name | default (include "openldap.ui.fullname" .) -}}
{{- else -}}
{{- .Values.serviceAccount.name | default "default" -}}
{{- end -}}
{{- end -}}

{{/*
Admin password Secret name: existingSecret when set, else the chart-created one.
*/}}
{{- define "openldap.adminSecretName" -}}
{{- .Values.auth.existingSecret | default (printf "%s-admin" (include "openldap.fullname" .)) -}}
{{- end -}}

{{/*
Server image reference.
*/}}
{{- define "openldap.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{/*
UI image reference.
*/}}
{{- define "openldap.ui.image" -}}
{{- printf "%s:%s" .Values.ui.image.repository (.Values.ui.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{/*
Whether replication is enabled: explicit replication.enabled override wins;
otherwise auto-enable when replicaCount > 1. Renders the literal string
"true" or "false".
*/}}
{{- define "openldap.replicationEnabled" -}}
{{- if hasKey .Values.replication "enabled" -}}
{{- .Values.replication.enabled -}}
{{- else -}}
{{- gt (int .Values.replicaCount) 1 -}}
{{- end -}}
{{- end -}}

{{/*
Comma-separated LDAP_REPLICATION_PEERS: every replica's headless-Service
FQDN, self included (see REPLICATION-CONTRACT.md D4).

CONTRACT (D7, orchestrator-verified): the image indexes into this list by
LDAP_SERVER_ID - 1 (LDAP_SERVER_ID = pod ordinal + 1) to find and exclude
itself. The list is therefore not just "the set of peers" — its ORDER is
part of the env var contract. It must be pod-ordinal ascending (0, 1, 2, ...,
replicaCount-1), dense (no gaps, no dropped/reordered entries). `until`
below walks $i ascending by construction — do not replace this with
anything that sorts, dedupes, or reorders the result (e.g. alphabetically,
or by `sortAlpha`), and do not exclude "self" here — the image does that
itself via the index, not by pattern-matching the URL.
*/}}
{{- define "openldap.replicationPeers" -}}
{{- $fullname := include "openldap.fullname" . -}}
{{- $headless := include "openldap.headlessName" . -}}
{{- $ns := .Release.Namespace -}}
{{- $domain := .Values.replication.clusterDomain -}}
{{- $count := int .Values.replicaCount -}}
{{- $peers := list -}}
{{- range $i := until $count -}}
{{- $peers = append $peers (printf "ldap://%s-%d.%s.%s.svc.%s:389" $fullname $i $headless $ns $domain) -}}
{{- end -}}
{{- join "," $peers -}}
{{- end -}}

{{/*
The data volume's size in bytes, for LDAP_DB_MAX_SIZE (mdb's olcDbMaxSize).

Sizing the map to the volume is the point: mdb reserves the map up front and,
under cgroup v2, the pages it dirties count against the container's memory
limit. A default 10 GiB map on a 2 Gi volume measured 690Mi RSS on a directory
holding five entries — most of a 1Gi limit, spent on space the filesystem
could never provide anyway.

Accepts Ki/Mi/Gi/Ti (and the k8s-legal bare-byte form). Anything else is a
hard error rather than a silent fallback, since a wrong map size surfaces much
later as an OOMKill.
*/}}
{{- define "openldap.dataVolumeBytes" -}}
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

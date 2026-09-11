{{/*
Chart name, truncated and DNS-1123-safe.
*/}}
{{- define "dratchet-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully-qualified app name — release name + chart name, unless the release
name already contains the chart name (avoids "dratchet-server-dratchet-server").
*/}}
{{- define "dratchet-server.fullname" -}}
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

{{- define "dratchet-server.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels, applied to every object this chart creates.
*/}}
{{- define "dratchet-server.labels" -}}
helm.sh/chart: {{ include "dratchet-server.chart" . }}
{{ include "dratchet-server.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels — kept separate from the full label set since selectors are
immutable on an existing Deployment; nothing here should ever change across
chart versions.
*/}}
{{- define "dratchet-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dratchet-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "dratchet-server.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "dratchet-server.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

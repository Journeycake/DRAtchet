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

{{/*
docs/adr/0001: queued-mail persistence. Where the mail store lives in the
container. Each volume is mounted at its own path and dratchetd keeps its
files in a "store" subdirectory it creates and owns, so it can restrict
that directory to itself (the mount root belongs to root, group fsGroup).
*/}}
{{- define "dratchet-server.mailDataRoot" -}}/var/lib/dratchetd{{- end -}}

{{- define "dratchet-server.fragmentDirs" -}}
{{- $root := include "dratchet-server.mailDataRoot" . -}}
{{- $dirs := list -}}
{{- range .Values.mailPersistence.fragments -}}
{{- $dirs = append $dirs (printf "%s/fragments-%s/store" $root .name) -}}
{{- end -}}
{{- join "," $dirs -}}
{{- end -}}

{{- define "dratchet-server.mailboxKeySecret" -}}
{{- default (printf "%s-mailbox-key" (include "dratchet-server.fullname" .)) .Values.mailPersistence.key.existingSecret -}}
{{- end -}}

{{/*
Fail at render time, not in a crash loop, when persistence is on but
can't work: dratchetd itself refuses to start without a key and two
different fragment directories.
*/}}
{{- define "dratchet-server.validateMailPersistence" -}}
{{- $mp := .Values.mailPersistence -}}
{{- if $mp.enabled -}}
{{- if and (not $mp.key.existingSecret) (not $mp.key.generate) -}}
{{- fail "mailPersistence.enabled needs a key: set mailPersistence.key.existingSecret, or mailPersistence.key.generate: true" -}}
{{- end -}}
{{- $names := list -}}
{{- range $mp.fragments -}}
{{- $names = append $names .name -}}
{{- end -}}
{{- if lt (len (uniq $names)) 2 -}}
{{- fail "mailPersistence.fragments needs at least two entries with different names" -}}
{{- end -}}
{{- if ne (len (uniq $names)) (len $names) -}}
{{- fail "mailPersistence.fragments names must all differ" -}}
{{- end -}}
{{- if or (lt (int $mp.flushInterval) 0) (gt (int $mp.flushInterval) 15) -}}
{{- fail "mailPersistence.flushInterval must be between 0 and 15 seconds" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Expand the name of the chart.
*/}}
{{- define "authplane.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "authplane.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "authplane.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "authplane.labels" -}}
helm.sh/chart: {{ include "authplane.chart" . }}
{{ include "authplane.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "authplane.selectorLabels" -}}
app.kubernetes.io/name: {{ include "authplane.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Container image.
*/}}
{{- define "authplane.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "authplane.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "authplane.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Config Secret name.
*/}}
{{- define "authplane.configSecretName" -}}
{{- if .Values.existingConfigSecret }}
{{- .Values.existingConfigSecret }}
{{- else }}
{{- printf "%s-config" (include "authplane.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Secrets Secret name (session secret, admin API key).
*/}}
{{- define "authplane.secretsName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- printf "%s-secrets" (include "authplane.fullname" .) }}
{{- end }}
{{- end }}

{{/*
PostgreSQL DSN.
Constructs the DSN from subchart or externalDatabase values.
*/}}
{{- define "authplane.postgresDSN" -}}
{{- if .Values.postgresql.enabled }}
{{- $host := printf "%s-postgresql" .Release.Name -}}
{{- $port := "5432" -}}
{{- $user := .Values.postgresql.auth.username | urlquery -}}
{{- $db := .Values.postgresql.auth.database | urlquery -}}
{{- printf "postgres://%s:$(PGPASSWORD)@%s:%s/%s?sslmode=disable" $user $host $port $db }}
{{- else if .Values.externalDatabase.host }}
{{- $host := .Values.externalDatabase.host -}}
{{- $port := .Values.externalDatabase.port | toString -}}
{{- $user := .Values.externalDatabase.user | urlquery -}}
{{- $db := .Values.externalDatabase.database | urlquery -}}
{{- $sslmode := .Values.externalDatabase.sslmode -}}
{{- printf "postgres://%s:$(PGPASSWORD)@%s:%s/%s?sslmode=%s" $user $host $port $db $sslmode }}
{{- end }}
{{- end }}

{{/*
PostgreSQL host for pg_isready init container.
*/}}
{{- define "authplane.postgresHost" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "%s-postgresql" .Release.Name }}
{{- else }}
{{- .Values.externalDatabase.host }}
{{- end }}
{{- end }}

{{/*
PostgreSQL port for pg_isready init container.
*/}}
{{- define "authplane.postgresPort" -}}
{{- if .Values.postgresql.enabled }}
{{- "5432" }}
{{- else }}
{{- .Values.externalDatabase.port | toString }}
{{- end }}
{{- end }}

{{/*
Vault signing Secret name.
*/}}
{{- define "authplane.vaultSigningSecretName" -}}
{{- if .Values.vault.signing.existingSecret }}
{{- .Values.vault.signing.existingSecret }}
{{- else }}
{{- printf "%s-vault-signing" (include "authplane.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Vault data encryption Secret name.
*/}}
{{- define "authplane.vaultEncryptionSecretName" -}}
{{- if .Values.vault.dataEncryption.existingSecret }}
{{- .Values.vault.dataEncryption.existingSecret }}
{{- else }}
{{- printf "%s-vault-encryption" (include "authplane.fullname" .) }}
{{- end }}
{{- end }}

{{/*
AES master-key data-encryption Secret name.
*/}}
{{- define "authplane.aesMasterSecretName" -}}
{{- if .Values.secrets.dataEncryption.existingSecret }}
{{- .Values.secrets.dataEncryption.existingSecret }}
{{- else }}
{{- printf "%s-data-enc" (include "authplane.fullname" .) }}
{{- end }}
{{- end }}

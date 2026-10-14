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

{{/*
Renders "true" when the server will use the keyfile signing store with its
key_path inside the /data volume (relative paths resolve against the image's
/data working directory). AUTHPLANE_SIGNING_KEY_STORE / _KEY_PATH entries in
extraEnv override the config block, as they do in the server. Anything the
chart cannot see through renders "" so it is never flagged: an
existingConfigSecret (the config block is ignored), Vault signing (the chart
sets the key store by env var), or an extraEnv entry taken from valueFrom.
An entry with no value, or a null one, sets the variable to "", which the
server treats as the keyfile store (or a key path relative to /data).
*/}}
{{- define "authplane.keyfileInDataVolume" -}}
{{- $unknown := or .Values.existingConfigSecret .Values.vault.signing.enabled -}}
{{- $store := toString (.Values.config.signing.key_store | default "keyfile") -}}
{{- $path := toString (.Values.config.signing.key_path | default "data/keys") -}}
{{- range .Values.extraEnv }}
{{- if has (toString .name) (list "AUTHPLANE_SIGNING_KEY_STORE" "AUTHPLANE_SIGNING_KEY_PATH") }}
{{- if hasKey . "valueFrom" }}
{{- $unknown = true }}
{{- else }}
{{- /* A missing or null value sets the variable to "", as Kubernetes does. */}}
{{- $v := "" }}
{{- if not (kindIs "invalid" .value) }}
{{- $v = toString .value }}
{{- end }}
{{- if eq (toString .name) "AUTHPLANE_SIGNING_KEY_STORE" }}
{{- $store = $v | default "keyfile" }}
{{- else }}
{{- $path = $v }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- $inData := or (not (hasPrefix "/" $path)) (eq $path "/data") (hasPrefix "/data/" $path) -}}
{{- if and (not $unknown) (eq $store "keyfile") $inData -}}
true
{{- end -}}
{{- end }}

{{/*
Renders "true" when keyfile signing keys live in the pod's emptyDir
(keyfileInDataVolume with persistence off): every pod generates its own key,
and generates a new one on restart.
*/}}
{{- define "authplane.signingKeysInEmptyDir" -}}
{{- if and (eq (include "authplane.keyfileInDataVolume" .) "true") (not .Values.persistence.enabled) -}}
true
{{- end -}}
{{- end }}

{{- /* Copyright Seaionl Inc. and CertPing contributors
       SPDX-License-Identifier: Apache-2.0 */ -}}

{{- define "certping.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "certping.labels" -}}
app.kubernetes.io/part-of: certping
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "certping.selector" -}}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "certping.image" -}}
{{- printf "%s/certping-%s:%s" .root.Values.image.registry .name (default .root.Chart.AppVersion .root.Values.image.tag) -}}
{{- end -}}

{{- define "certping.url" -}}
{{- required "Set url, for example --set url=https://certping.example.com" .Values.url | trimSuffix "/" -}}
{{- end -}}

{{- define "certping.host" -}}
{{- include "certping.url" . | trimPrefix "https://" | trimPrefix "http://" | splitList "/" | first | splitList ":" | first -}}
{{- end -}}

{{- define "certping.dbHost" -}}
{{- if .Values.postgres.enabled -}}{{ include "certping.fullname" . }}-postgres{{- else -}}{{ required "Set database.host or enable postgres" .Values.database.host }}{{- end -}}
{{- end -}}

{{- define "certping.redisHost" -}}
{{- if .Values.redis.enabled -}}{{ include "certping.fullname" . }}-redis{{- else -}}{{ required "Set redis.host or enable redis" .Values.redis.host }}{{- end -}}
{{- end -}}

{{/* Container security context for the bundled PostgreSQL and Valkey. */}}
{{- define "certping.dataContainerSecurityContext" -}}
runAsNonRoot: true
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/* Holds a pod until PostgreSQL accepts connections, so a first install does not crash-loop. */}}
{{- define "certping.waitForDatabase" -}}
initContainers:
  - name: wait-for-database
    image: {{ .Values.postgres.image }}
    imagePullPolicy: {{ .Values.image.pullPolicy }}
    command: ["sh", "-c", "until pg_isready -q -h \"$DB_HOST\" -p \"$DB_PORT\"; do sleep 2; done"]
    env:
      - name: DB_HOST
        value: {{ include "certping.dbHost" . | quote }}
      - name: DB_PORT
        value: {{ .Values.database.port | quote }}
    securityContext: {{- toYaml .Values.containerSecurityContext | nindent 6 }}
    resources:
      requests: {cpu: 10m, memory: 16Mi}
      limits: {memory: 32Mi}
{{- end -}}

{{/* A NetworkPolicy peer for the release's pods of one component. */}}
{{- define "certping.peer" -}}
- podSelector:
    matchLabels:
      {{- include "certping.selector" . | nindent 6 }}
{{- end -}}

{{/* Environment shared by the Java services. */}}
{{- define "certping.javaEnv" -}}
- name: SPRING_PROFILES_ACTIVE
  value: selfhosted
- name: OTEL_JAVAAGENT_ENABLED
  value: "false"
- name: CERTPING_URL
  value: {{ include "certping.url" . | quote }}
- name: DB_URL
  value: {{ printf "jdbc:postgresql://%s:%v/%s" (include "certping.dbHost" .) .Values.database.port .Values.database.name | quote }}
- name: DB_USERNAME
  value: {{ .Values.database.username | quote }}
{{- end -}}


{{/* Extra CA certificates (extraCaCerts): "true" when a ConfigMap or Secret is named. */}}
{{- define "certping.extraCa.enabled" -}}
{{- if and .Values.extraCaCerts.configMap .Values.extraCaCerts.secret -}}
{{- fail "extraCaCerts: set configMap or secret, not both" -}}
{{- end -}}
{{- if or .Values.extraCaCerts.configMap .Values.extraCaCerts.secret -}}true{{- end -}}
{{- end -}}

{{/* Container command that runs files/java-entrypoint.sh before the image's own start. */}}
{{- define "certping.extraCa.command" -}}
command: ["/bin/sh", "/etc/certping/entrypoint/java-entrypoint.sh"]
{{- end -}}

{{- define "certping.extraCa.env" -}}
- name: CERTPING_EXTRA_CA_CERTS
  value: {{ printf "/etc/certping/extra-ca/%s" .Values.extraCaCerts.key | quote }}
{{- end -}}

{{- define "certping.extraCa.mounts" -}}
- name: java-entrypoint
  mountPath: /etc/certping/entrypoint
  readOnly: true
- name: extra-ca
  mountPath: /etc/certping/extra-ca
  readOnly: true
{{- end -}}

{{- define "certping.extraCa.volumes" -}}
- name: java-entrypoint
  configMap:
    name: {{ include "certping.fullname" . }}-java-entrypoint
- name: extra-ca
  {{- if .Values.extraCaCerts.secret }}
  secret:
    secretName: {{ .Values.extraCaCerts.secret }}
  {{- else }}
  configMap:
    name: {{ .Values.extraCaCerts.configMap }}
  {{- end }}
{{- end -}}

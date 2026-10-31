{{- define "ouf-service.fullname" -}}
{{- default .Release.Name .Values.fullnameOverride -}}
{{- end -}}

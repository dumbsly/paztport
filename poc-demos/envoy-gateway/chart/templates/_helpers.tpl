{{- /*
Copyright 2026 The Paztport Authors
SPDX-License-Identifier: Apache-2.0
*/ -}}

{{- /* The labels every object the chart makes carries. */ -}}
{{- define "edge.labels" -}}
app.kubernetes.io/name: {{ .Values.name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: processor
app.kubernetes.io/part-of: paztport
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- /* The labels that select the processor's pods. */ -}}
{{- define "edge.selector" -}}
app.kubernetes.io/name: {{ .Values.name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- /* The processor's image: by digest when one is given, else by tag. */ -}}
{{- define "edge.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ required "image.tag or image.digest is required" .Values.image.tag }}
{{- end -}}
{{- end -}}

{{- /* The Secret holding the edge's private key, as edge.key. */ -}}
{{- define "edge.keySecret" -}}
{{- .Values.material.existingKeySecret | default (printf "%s-key" .Values.name) -}}
{{- end -}}

{{- /* The kubernetes.io/tls Secret holding the processor's server certificate and key. */ -}}
{{- define "edge.tlsSecret" -}}
{{- .Values.tls.existingSecret | default (printf "%s-tls" .Values.name) -}}
{{- end -}}

{{- /* The ConfigMap holding the mesh CA's certificate, as ca.crt. */ -}}
{{- define "edge.caConfigMap" -}}
{{- .Values.tls.existingCAConfigMap | default (printf "%s-ca" .Values.name) -}}
{{- end -}}

{{- /* The routes file: one <namespace>/<httproute>=<receiver> a line. */ -}}
{{- define "edge.routes" -}}
{{- $lines := list -}}
{{- range required "routes must map at least one HTTPRoute" .Values.routes }}
{{- $route := required "each route needs an httpRoute" .httpRoute }}
{{- $line := printf "%s/%s=%s" $.Release.Namespace $route (required "each route needs a receiver" .receiver) }}
{{- range $lines }}
{{- if hasPrefix (printf "%s/%s=" $.Release.Namespace $route) . }}
{{- fail (printf "the HTTPRoute %s is mapped twice" $route) }}
{{- end }}
{{- end }}
{{- $lines = append $lines $line }}
{{- end }}
{{- join "\n" $lines }}
{{- end -}}

{{- /* The paths of a list of policy files, as the processor takes them: comma-separated. */ -}}
{{- define "edge.files" -}}
{{- $paths := list -}}
{{- range $i, $_ := .list }}
{{- $paths = append $paths (printf "/etc/paztport/policy/%s-%d.json" $.prefix $i) }}
{{- end }}
{{- join "," $paths -}}
{{- end -}}

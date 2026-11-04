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
{{- range .Values.routes }}
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

{{- /*
The HTTPRoutes the processor is attached to, one name a line: those in routes, then those in extraRoutes. A name in
both is refused.
*/ -}}
{{- define "edge.attached" -}}
{{- $names := list -}}
{{- range .Values.routes }}{{ $names = append $names .httpRoute }}{{ end -}}
{{- range .Values.extraRoutes }}
{{- if has . $names }}{{ fail (printf "the HTTPRoute %s is in both routes and extraRoutes" .) }}{{ end }}
{{- $names = append $names . }}
{{- end }}
{{- join "\n" $names }}
{{- end -}}

{{- /* The paths of a list of policy files, as the processor takes them: comma-separated. */ -}}
{{- define "edge.files" -}}
{{- $paths := list -}}
{{- range $i, $_ := .list }}
{{- $paths = append $paths (printf "/etc/paztport/policy/%s-%d.json" $.prefix $i) }}
{{- end }}
{{- join "," $paths -}}
{{- end -}}

{{- /*
Refuses values the processor would not start with, or that would leave the edge without a limit: no route mapped,
no keyring or root, and a body limit that is not a whole number of bytes from 1 to 1 GiB (1073741824), the processor's
own bounds. bodyLimit is a plain number of bytes, such as 1048576, as a number or a string of digits: a quantity such
as 1Mi, a fraction or anything else is refused. It refuses as well no Gateway for the NetworkPolicy to admit the
Envoy pods of, and a mergeType Envoy Gateway does not take for an EnvoyExtensionPolicy.
*/ -}}
{{- define "edge.validate" -}}
{{- if not .Values.routes }}{{ fail "routes must map at least one HTTPRoute" }}{{ end }}
{{- if and (not .Values.gateway.name) (not .Values.gateway.envoyPodLabels) }}
{{- fail "gateway.name (or gateway.envoyPodLabels) is required" }}
{{- end }}
{{- with .Values.mergeType }}
{{- if not (has . (list "StrategicMerge" "JSONMerge")) }}
{{- fail (printf "mergeType %v is not StrategicMerge or JSONMerge" .) }}
{{- end }}
{{- end }}
{{- if not .Values.material.keyrings }}{{ fail "material.keyrings needs at least one keyring" }}{{ end }}
{{- if not .Values.material.roots }}{{ fail "material.roots needs at least one root" }}{{ end }}
{{- $v := .Values.bodyLimit }}
{{- $limit := $v | int64 }}
{{- $whole := false }}
{{- if kindIs "string" $v }}{{ $whole = regexMatch "^[0-9]+$" $v }}
{{- else if kindIs "float64" $v }}{{ $whole = eq $v (float64 $limit) }}
{{- else if or (kindIs "int" $v) (kindIs "int64" $v) }}{{ $whole = true }}
{{- end }}
{{- if or (not $whole) (le $limit 0) (gt $limit 1073741824) }}
{{- fail (printf "bodyLimit %v is not a whole number of bytes from 1 to 1073741824, such as 1048576"
  .Values.bodyLimit) }}
{{- end }}
{{- end -}}

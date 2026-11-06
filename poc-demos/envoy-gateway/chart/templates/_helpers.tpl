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
The HTTPRoutes the processor is attached to, one name a line: those in routes whose attach is not false, then those
in extraRoutes. The output is empty when there are none. A name in both routes (attached or not) and extraRoutes, or
twice in extraRoutes, is refused.
*/ -}}
{{- define "edge.attached" -}}
{{- $mapped := list -}}
{{- $names := list -}}
{{- range .Values.routes }}
{{- $mapped = append $mapped .httpRoute }}
{{- if or (not (hasKey . "attach")) .attach }}{{ $names = append $names .httpRoute }}{{ end }}
{{- end }}
{{- range .Values.extraRoutes }}
{{- if has . $mapped }}{{ fail (printf "the HTTPRoute %s is in both routes and extraRoutes" .) }}{{ end }}
{{- if has . $names }}{{ fail (printf "the HTTPRoute %s is listed twice in extraRoutes" .) }}{{ end }}
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
A whole number, as a number or a string of decimal digits (as --set-string or a quoted YAML value gives): prints
it, or nothing for anything else: a fraction, a bool, nothing, or a string that is not plain digits (no leading zero,
which sprig would read as octal, and no more than 18 digits, which could pass int64). Its range is the caller's.
*/ -}}
{{- define "edge.whole" -}}
{{- $v := . -}}
{{- if kindIs "string" $v }}{{ if regexMatch "^[1-9][0-9]{0,17}$" $v }}{{ $v | int64 }}{{ end }}
{{- else if kindIs "float64" $v }}{{ if and (eq $v (floor $v)) (ge $v -1e15) (le $v 1e15) }}{{ $v | int64 }}{{ end }}
{{- else if or (kindIs "int" $v) (kindIs "int64" $v) }}{{ $v | int64 }}
{{- end }}
{{- end -}}

{{- /* A value as the message shows it: a whole float without an exponent, anything else as it is. */ -}}
{{- define "edge.show" -}}
{{- if and (kindIs "float64" .) (eq . (floor .)) (ge . -1e15) (le . 1e15) }}{{ . | int64 }}{{ else }}{{ . }}{{ end }}
{{- end -}}

{{- /*
Refuses values the processor would not start with, or that would leave the edge without a limit: no route mapped, an
attach that is not true or false, no keyring or root, and a body limit that is not a whole number of bytes from 1 to 1
GiB (1073741824), the processor's own bounds. bodyLimit is a plain number of bytes, such as 1048576, as a number or a
string of digits without a leading zero: a quantity such as 1Mi, a fraction or anything else is refused. It refuses as
well no Gateway for the NetworkPolicy to admit the Envoy pods of, and a mergeType Envoy Gateway does not take for a
policy on routes (it refuses Replace).
*/ -}}
{{- define "edge.validate" -}}
{{- if not .Values.routes }}{{ fail "routes must map at least one HTTPRoute" }}{{ end }}
{{- range $i, $route := .Values.routes }}
{{- if and (hasKey $route "attach") (not (kindIs "bool" $route.attach)) }}
{{- fail (printf "routes[%d].attach must be true or false" $i) }}
{{- end }}
{{- end }}
{{- if and (not .Values.gateway.name) (not .Values.gateway.envoyPodLabels) }}
{{- fail "gateway.name (or gateway.envoyPodLabels) is required" }}
{{- end }}
{{- with .Values.mergeType }}
{{- if not (has . (list "StrategicMerge" "JSONMerge")) }}
{{- fail (printf "mergeType %v is not StrategicMerge or JSONMerge" .) }}
{{- end }}
{{- end }}
{{- with .Values.backendTrafficPolicyMergeType }}
{{- if not (has . (list "StrategicMerge" "JSONMerge")) }}
{{- fail (printf "backendTrafficPolicyMergeType %v is not StrategicMerge, JSONMerge or empty" .) }}
{{- end }}
{{- end }}
{{- if or (kindIs "invalid" .Values.healthCheck.interval) (eq (trim (toString .Values.healthCheck.interval)) "") }}
{{- fail "healthCheck.interval is empty: Envoy Gateway would use 3s unasked; give a duration such as 1s" }}
{{- end }}
{{- range $name := list "unhealthyThreshold" "healthyThreshold" }}
{{- $t := index $.Values.healthCheck $name }}
{{- if kindIs "invalid" $t }}
{{- fail (printf "healthCheck.%s is not set: a whole number from 1 to 4294967295" $name) }}
{{- end }}
{{- $n := include "edge.whole" $t }}
{{- if or (not $n) (lt ($n | int64) 1) (gt ($n | int64) 4294967295) }}
{{- fail (printf "healthCheck.%s %v is not a whole number from 1 to 4294967295, in digits with no leading zero"
  $name (include "edge.show" $t)) }}
{{- end }}
{{- end }}
{{- if not .Values.material.keyrings }}{{ fail "material.keyrings needs at least one keyring" }}{{ end }}
{{- if not .Values.material.roots }}{{ fail "material.roots needs at least one root" }}{{ end }}
{{- $whole := include "edge.whole" .Values.bodyLimit }}
{{- $limit := $whole | int64 }}
{{- if or (not $whole) (le $limit 0) (gt $limit 1073741824) }}
{{- fail (printf "bodyLimit %v is not a whole number of bytes from 1 to 1073741824, such as 1048576"
  (include "edge.show" .Values.bodyLimit)) }}
{{- end }}
{{- end -}}

<#-- Copyright 2026 The Paztport Authors
     SPDX-License-Identifier: Apache-2.0

     META-INF/THIRD-PARTY.txt of a jar that bundles third-party components, written by license-maven-plugin
     add-third-party. dependencyMap maps each bundled component (a MavenProject) to the licences it is used under. -->
Third-party components bundled in this jar. Each line gives the licence the component is used under, its name,
its Maven Central coordinates (group:artifact:version; its source is published there as the -sources.jar beside
the jar) and its project URL. META-INF/LICENSE holds the Apache-2.0 text, and META-INF/licenses/ the text of every
other licence named here.

<#list dependencyMap as e>
     <#list e.getValue() as licence>(${licence}) </#list>${e.getKey().name!e.getKey().artifactId} (${e.getKey().groupId}:${e.getKey().artifactId}:${e.getKey().version} - ${e.getKey().url!"no project URL"})
</#list>

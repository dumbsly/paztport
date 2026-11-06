<#-- Copyright 2026 The Paztport Authors
     SPDX-License-Identifier: Apache-2.0

     META-INF/THIRD-PARTY.txt of a jar that bundles third-party components, written by license-maven-plugin
     add-third-party. dependencyMap maps each bundled component (a MavenProject) to the licences it is used under;
     a component with more than one stops the build. -->
Third-party components bundled in this jar. Each line gives the licence the component is used under, its name,
its Maven Central coordinates (group:artifact:version) and its project URL. Where Maven Central holds a component's
source, it is the -sources.jar beside the jar at those coordinates, available under the licence the line names.
META-INF/LICENSE holds the Apache-2.0 text, and META-INF/licenses/ the text of every other licence named here.

<#list dependencyMap as e>
<#if (e.getValue()?size != 1)><#stop "${e.getKey().groupId}:${e.getKey().artifactId}:${e.getKey().version} is listed under ${e.getValue()?size} licences; licenses/overrides.properties and licenses/download-licenses.xml name the one it is used under"></#if>
     (${e.getValue()?first}) ${e.getKey().name!e.getKey().artifactId} (${e.getKey().groupId}:${e.getKey().artifactId}:${e.getKey().version} - ${e.getKey().url!"no project URL"})
</#list>

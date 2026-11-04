// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package material loads the edge's policy material and checks it before the edge stamps anything: its
// private key, the keyrings and roots its receivers pin, its proof bundle and the routes it stamps for
// ([Load]), and whether the material is still current ([Set.Ready], [Set.TimeLeft]). Every file is handed
// to the SDK's loaders as it is; nothing here reads Paztport's JSON itself.
package material

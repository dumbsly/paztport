// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.responder;

/** Isolates a suspect container and starts a clean replacement. */
public interface Quarantiner {

    void quarantine(String suspectSvc, String suspectInst);
}

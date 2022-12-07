/**************************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#pragma once

/* Keyple Card Calypso */
#include "CalypsoSamCommandException.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Indicates that the security conditions are not fulfilled (e.g. busy status).
 *
 * @since 2.2.0
 */
class CalypsoSamSecurityContextException final : public CalypsoSamCommandException {
public:
  /**
     * (package-private)<br>
     *
     * @param message the message to identify the exception context.
     * @param command the Calypso SAM command.
     * @param statusWord the status word.
     * @since 2.2.0
     */
    CalypsoSamSecurityContextException(const std::string& message, 
                                       const CalypsoSamCommand& command, 
                                       const std::shared_ptr<int> statusWord);
}

}
}
}

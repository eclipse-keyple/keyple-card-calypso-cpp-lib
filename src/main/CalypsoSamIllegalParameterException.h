/**************************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/                        *
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
 * Indicates that some input parameter is not accepted by the SAM.
 *
 * @since 2.0.0
 */
class CalypsoSamIllegalParameterException final : public CalypsoSamCommandException {
public:
    /**
     * (package-private)<br>
     *
     * @param message the message to identify the exception context.
     * @param command the Calypso SAM command.
     * @param statusWord the status word.
     * @since 2.0.0
     */
    CalypsoSamIllegalParameterException(const std::string& message,
                                       const CalypsoSamCommand& command,
                                       const std::shared_ptr<int> statusWord)
    : CalypsoSamCommandException(message, command, statusWord) {}
};

}
}
}

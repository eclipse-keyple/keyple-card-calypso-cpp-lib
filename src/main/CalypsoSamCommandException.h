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
#include "CalypsoApduCommandException.h"
#include "CalypsoSamCommand.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Parent abstract class of all Keyple SAM APDU commands exceptions.
 *
 * @since 2.0.0
 */
class CalypsoSamCommandException : public CalypsoApduCommandException {
public:
    /**
     * (package-private)<br>
     * 
     * @param message the message to identify the exception context.
     * @param command the Calypso SAM command.
     * @param statusWord the status word (optional).
     * @since 2.0.0
     */
    CalypsoSamCommandException(const std::string& message,
                               const CalypsoSamCommand& command,
                               const std::shared_ptr<int> statusWord)
    : CalypsoApduCommandException(message, command, statusWord) {}
};

}
}
}

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
#include "CalypsoSamCommand.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * This exception indicates that the length of the response is not equal to the value of the LE
 * field in the request.
 *
 * @since 2.1.1
 */
class CalypsoSamUnexpectedResponseLengthException : public CalypsoSamCommandException {
public:
    /**
     * (package-private)<br>
     * Constructor allowing to set a message, the command and the status word.
     *
     * @param message the message to identify the exception context.
     * @param command the card command.
     * @param statusWord the status word.
     * @since 2.1.1
     */
    CalypsoSamUnexpectedResponseLengthException(const std::string& message,
                                                const CalypsoSamCommand& command,
                                                const std::shared_ptr<int> statusWord)
    : CalypsoSamCommandException(message, command, statusWord) {}
};

}
}
}

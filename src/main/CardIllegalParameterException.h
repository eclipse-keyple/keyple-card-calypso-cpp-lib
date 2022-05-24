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
#include "CardCommandException.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Indicates that some input parameter is not accepted by the card.
 *
 * @since 2.0.0
 */
class CardIllegalParameterException final : public CardCommandException {
public:
    /**
     * (package-private)<br>
     *
     * @param message the message to identify the exception context.
     * @param command the Calypso card command.
     * @param statusWord the status word.
     * @since 2.0.0
     */
    CardIllegalParameterException(const std::string& message,
                                  const CalypsoCardCommand& command,
                                  const std::shared_ptr<int> statusWord)
    : CardCommandException(message, command, statusWord) {}
};

}
}
}

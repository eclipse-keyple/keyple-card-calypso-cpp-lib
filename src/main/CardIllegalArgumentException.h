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
 * Indicates that the input user data do not allow to build a syntactically correct command (e.g.
 * SFI too large, record number out of bounds,...).
 *
 * @since 2.0.0
 */
class CardIllegalArgumentException final : public CardCommandException {
public:
    /**
     * (package-private)<br>
     *
     * @param message the message to identify the exception context.
     * @param command the Calypso card command.
     * @since 2.0.0
     */
    CardIllegalArgumentException(const std::string& message, const CalypsoCardCommand& command)
    : CardCommandException(message, command, nullptr) {}
};

}
}
}

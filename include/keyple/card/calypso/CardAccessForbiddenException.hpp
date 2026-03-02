/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * See the NOTICE file(s) distributed with this work for additional           *
 * information regarding copyright ownership.                                 *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the Eclipse Public License 2.0 which is available at              *
 * http://www.eclipse.org/legal/epl-2.0                                       *
 *                                                                            *
 * SPDX-License-Identifier: EPL-2.0                                           *
 ******************************************************************************/

#pragma once

#include <string>

#include "keyple/card/calypso/CardCommandException.hpp"
#include "keyple/card/calypso/CardCommandRef.hpp"

namespace keyple {
namespace card {
namespace calypso {

/**
 * Indicates that the access is forbidden (e.g. Never access mode, DF is
 * invalidated,...).
 *
 * @since 2.0.0
 */
class CardAccessForbiddenException final : public CardCommandException {
public:
    /**
     * @param message the message to identify the exception context.
     * @param command the Calypso card command.
     * @since 2.0.0
     */
    CardAccessForbiddenException(
        const std::string& message, const CardCommandRef& command)
    : CardCommandException(message, command)
    {
    }
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */

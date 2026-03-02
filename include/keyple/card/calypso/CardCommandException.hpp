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

#include "keyple/card/calypso/CardCommandRef.hpp"
#include "keyple/core/util/cpp/exception/Exception.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::exception::Exception;

/**
 * Parent abstract class of all Calypso card APDU commands exceptions.
 *
 * @since 2.0.0
 */
class CardCommandException : public Exception {
public:
    /**
     * @param message the message to identify the exception context.
     * @param commandRef the Calypso card command.
     * @since 2.0.0
     */
    CardCommandException(
        const std::string& message, const CardCommandRef& command)
    : Exception(message)
    , mCommandRef(command)
    {
    }

    /**
     * Gets the command
     *
     * @return A not null reference.
     * @since 2.0.0
     */
    const CardCommandRef&
    getCommandRef() const
    {
        return mCommandRef;
    }

private:
    /** */
    const CardCommandRef mCommandRef;
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */

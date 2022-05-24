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

/* Keyple Core Utils */
#include "Exception.h"

/* Keyple Card Calypso */
#include "CardCommand.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util::cpp::exception;

/**
 * This exception is the parent abstract class of all card APDU commands exceptions.
 *
 * @since 2.0.0
 */
class CalypsoApduCommandException : public Exception {
public:
    /**
     * Gets the command
     *
     * @return A not null reference.
     * @since 2.0.0
     */
    const CardCommand& getCommand() const
    {
        return mCommand;
    }

    /**
     * Gets the status word
     *
     * @return A nullable reference
     * @since 2.0.0
     */
    const std::shared_ptr<int> getStatusWord() const
    {
        return mStatusWord;
    }

protected:
    /**
     * Constructor allowing to set the error message and the reference to the command
     *
     * @param message the message to identify the exception context (Should not be null).
     * @param command the command.
     * @param statusWord the status word.
     * @since 2.0.0
     */
    CalypsoApduCommandException(const std::string& message,
                                const CardCommand& command,
                                const std::shared_ptr<int> statusWord)
    : Exception(message), mCommand(command), mStatusWord(statusWord) {}

private:
    /**
     *
     */
    const CardCommand& mCommand;

    /**
     *
     */
    const std::shared_ptr<int> mStatusWord;
};

}
}
}

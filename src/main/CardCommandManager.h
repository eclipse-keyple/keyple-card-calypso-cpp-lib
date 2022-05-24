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

/* Keyple Core Util */
#include "LoggerFactory.h"

/* Keyple Card Calypso */
#include "AbstractCardCommand.h"

/* Calypsonet Terminal Calypso */
#include "SvOperation.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;
using namespace keyple::core::util::cpp;

/**
 * (package-private)<br>
 * Handles a list of AbstractCardCommand updated by the "prepare" methods of
 * CardTransactionManager.
 *
 * <p>Keeps commands between the time the commands are created and the time their responses are
 * parsed.
 *
 * <p>A flag (preparedCommandsProcessed) is used to manage the reset of the command list. It allows
 * the commands to be kept until the application creates a new list of commands.
 *
 * <p>This flag is set when invoking the method notifyCommandsProcessed and reset when a new
 * AbstractCardCommand is added.
 *
 * @since 2.0.0
 */
class CardCommandManager {
public:
    /**
     * (package-private)<br>
     * Constructor
     */
    CardCommandManager();

    /**
     * (package-private)<br>
     * Add a regular command to the list.
     *
     * @param command the command.
     * @since 2.0.0
     */
    void addRegularCommand(const std::shared_ptr<AbstractCardCommand> command);

    /**
     * (package-private)<br>
     * Add a StoredValue command to the list.
     *
     * <p>Set up a mini state machine to manage the scheduling of Stored Value commands.
     *
     * <p>The SvOperation and SvAction are also used to check the consistency of the
     * SV process.
     *
     * <p>The svOperationPending flag is set when an SV operation (Reload/Debit/Undebit) command is
     * added.
     *
     * @param command the StoredValue command.
     * @param svOperation the type of the current SV operation (Reload/Debit/Undebit).
     * @throws IllegalStateException if the provided command is not an SV command or not properly
     *         used.
     * @since 2.0.0
     */
    void addStoredValueCommand(const std::shared_ptr<AbstractCardCommand> command,
                               const SvOperation svOperation);

    /**
     * (package-private)<br>
     * Informs that the commands have been processed.
     *
     * <p>Just record the information. The initialization of the list of commands will be done only
     * the next time a command is added, this allows access to the commands contained in the list.
     *
     * @since 2.0.0
     */
    void notifyCommandsProcessed();

    /**
     * (package-private)<br>
     *
     * @return The current AbstractCardCommand list
     * @since 2.0.0
     */
    const std::vector<std::shared_ptr<AbstractCardCommand>>& getCardCommands() const;

    /**
     * (package-private)<br>
     *
     * @return True if the CardCommandManager has commands
     * @since 2.0.0
     */
    bool hasCommands() const;
    /**
     * (package-private)<br>
     * Indicates whether an SV Operation has been completed (Reload/Debit/Undebit requested) <br>
     * This method is dedicated to triggering the signature verification after an SV transaction has
     * been executed. It is a single-use method, as the flag is systematically reset to false after
     * it is called.
     *
     * @return True if a "reload" or "debit" command has been requested
     * @since 2.0.0
     */
    bool isSvOperationCompleteOneTime();

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger = LoggerFactory::getLogger(typeid(CardCommandManager));

    /**
     * The list to contain the prepared commands
     */
    std::vector<std::shared_ptr<AbstractCardCommand>> mCardCommands;

    /**
     *
     */
    CalypsoCardCommand mSvLastCommand;

    /**
     *
     */
    SvOperation mSvOperation;

    /**
     *
     */
    bool mSvOperationComplete;
};

}
}
}

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

#include "CardCommandManager.h"

/* Keyple Card Calypso */
#include "CalypsoCardCommand.h"

/* Keyple Core Util */
#include "IllegalStateException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util::cpp::exception;

CardCommandManager::CardCommandManager()
: mSvLastCommand(CalypsoCardCommand::NONE), mSvOperationComplete(false) {}

void CardCommandManager::addRegularCommand(const std::shared_ptr<AbstractCardCommand> command)
{
    mCardCommands.push_back(command);
}

void CardCommandManager::addStoredValueCommand(const std::shared_ptr<AbstractCardCommand> command,
                                               const SvOperation svOperation)
{
    /* Check the logic of the SV command sequencing */
    const CalypsoCardCommand& cmd = command->getCommandRef();
    if (cmd == CalypsoCardCommand::SV_GET) {
        mSvOperation = svOperation;
    } else if (cmd == CalypsoCardCommand::SV_RELOAD ||
               cmd == CalypsoCardCommand::SV_DEBIT ||
               cmd == CalypsoCardCommand::SV_UNDEBIT) {
        /*
         * CL-SV-GETDEBIT.1
         * CL-SV-GETRLOAD.1
         */
        if (!mCardCommands.empty()) {
            throw IllegalStateException("This SV command can only be placed in the first position" \
                                        " in the list of prepared commands");
        }

        if (mSvLastCommand != CalypsoCardCommand::SV_GET) {
            throw IllegalStateException("This SV command must follow an SV Get command");
        }

        /* Here, we expect the command and the SV operation to be consistent */
        if (svOperation != mSvOperation) {
            mLogger->error("Sv operation = %, current command = %\n", mSvOperation, svOperation);
            throw IllegalStateException("Inconsistent SV operation.");
        }

        mSvOperationComplete = true;
    } else {
        throw IllegalStateException("An SV command is expected.");
    }

    mSvLastCommand = command->getCommandRef();

    mCardCommands.push_back(command);
}

void CardCommandManager::notifyCommandsProcessed()
{
    mCardCommands.clear();
}

const std::vector<std::shared_ptr<AbstractCardCommand>>& CardCommandManager::getCardCommands() const
{
    return mCardCommands;
}

bool CardCommandManager::hasCommands() const
{
    return !mCardCommands.empty();
}

bool CardCommandManager::isSvOperationCompleteOneTime()
{
    const bool flag = mSvOperationComplete;
    mSvOperationComplete = false;

    return flag;
}

}
}
}

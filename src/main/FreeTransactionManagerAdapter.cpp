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

#include "keyple/card/calypso/FreeTransactionManagerAdapter.hpp"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardConstant.hpp"
#include "keyple/card/calypso/CommandChangePin.hpp"
#include "keyple/card/calypso/CommandVerifyPin.hpp"
#include "keyple/core/plugin/CardIOException.hpp"
#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/exception/RuntimeException.hpp"
#include "keyple/core/util/cpp/exception/UnsupportedOperationException.hpp"
#include "keypop/calypso/card/transaction/UnexpectedCommandStatusException.hpp"
#include "keypop/calypso/crypto/legacysam/transaction/ReaderIOException.hpp"
#include "keypop/reader/CardCommunicationException.hpp"
#include "keypop/reader/ReaderCommunicationException.hpp"
#include "keypop/reader/selection/InvalidCardResponseException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::plugin::CardIOException;
using keyple::core::util::Assert;
using keyple::core::util::cpp::exception::RuntimeException;
using keyple::core::util::cpp::exception::UnsupportedOperationException;
using keypop::calypso::card::transaction::UnexpectedCommandStatusException;
using keypop::calypso::crypto::legacysam::transaction::ReaderIOException;
using keypop::reader::CardCommunicationException;
using keypop::reader::ReaderCommunicationException;
using keypop::reader::selection::InvalidCardResponseException;

const std::string FreeTransactionManagerAdapter::MSG_PIN_NOT_AVAILABLE
    = "PIN is not available for this card";

FreeTransactionManagerAdapter::FreeTransactionManagerAdapter(
    std::shared_ptr<ProxyReaderApi> cardReader,
    std::shared_ptr<CalypsoCardAdapter> card)
: TransactionManagerAdapter<FreeTransactionManager>(cardReader, card)
, mTransactionContext(
      std::make_shared<DtoAdapters::TransactionContextDto>(card))
, mCommandContext(
      std::make_shared<DtoAdapters::CommandContextDto>(false, false))
{
}

std::shared_ptr<DtoAdapters::TransactionContextDto>
FreeTransactionManagerAdapter::getTransactionContext() const
{
    return mTransactionContext;
}

std::shared_ptr<DtoAdapters::CommandContextDto>
FreeTransactionManagerAdapter::getCommandContext() const
{
    return mCommandContext;
}

int
FreeTransactionManagerAdapter::getPayloadCapacity() const
{
    return mCard->getPayloadCapacity();
}

void
FreeTransactionManagerAdapter::resetTransaction()
{
    mCommands.clear();
}

void
FreeTransactionManagerAdapter::prepareNewSecureSessionIfNeeded(
    const std::shared_ptr<Command>& /*command*/)
{
    /* NOP */
}

bool
FreeTransactionManagerAdapter::canConfigureReadOnOpenSecureSession() const
{
    return false;
}

// FreeTransactionManager&
// FreeTransactionManagerAdapter::processCommands(
//     keypop::calypso::card::transaction::ChannelControl channelControl)
// {
//     try {
//         return processCommands(
//             keypop::reader::valueOf(static_cast<int>(channelControl)));
//
//     } catch (const CardCommunicationException& e) {
//         throw CardIOException(e.what(), Exception(e.what()));
//
//     } catch (const ReaderCommunicationException& e) {
//         throw ReaderIOException(e.what(), e);
//
//     } catch (const InvalidCardResponseException& e) {
//         throw UnexpectedCommandStatusException(e.what(), e);
//     }
// }

FreeTransactionManager&
FreeTransactionManagerAdapter::processCommands(ChannelControl channelControl)
{
    if (mCommands.empty()) {
        return *this;
    }

    try {
        std::vector<std::shared_ptr<Command>> cardRequestCommands;
        for (auto& command : mCommands) {
            command->finalizeRequest();
            cardRequestCommands.push_back(command);
        }

        executeCardCommands(cardRequestCommands, channelControl);

    } catch (const RuntimeException& e) {
        resetTransaction();

        /* Finally */
        mCommands.clear();

        throw;
    }

    /* Finally */
    mCommands.clear();

    return *this;
}

FreeTransactionManager&
FreeTransactionManagerAdapter::prepareVerifyPin(
    const std::vector<std::uint8_t>& pin)
{
    try {
        Assert::getInstance().isEqual(
            pin.size(), CalypsoCardConstant::PIN_LENGTH, "PIN length");

        if (!mCard->isPinFeatureAvailable()) {
            throw UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
        }

        mCommands.push_back(
            std::make_shared<CommandVerifyPin>(
                getTransactionContext(), getCommandContext(), pin));

    } catch (const RuntimeException& e) {
        resetTransaction();
        throw;
    }

    return *this;
}

FreeTransactionManager&
FreeTransactionManagerAdapter::prepareChangePin(
    const std::vector<std::uint8_t>& newPin)
{
    try {
        Assert::getInstance().isEqual(
            newPin.size(), CalypsoCardConstant::PIN_LENGTH, "PIN length");
        if (!mCard->isPinFeatureAvailable()) {
            throw UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
        }

        // CL-PIN-MENCRYPT.1
        mCommands.push_back(
            std::make_shared<CommandChangePin>(
                getTransactionContext(), getCommandContext(), newPin));

    } catch (const RuntimeException& e) {
        resetTransaction();
        throw;
    }

    return *this;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */

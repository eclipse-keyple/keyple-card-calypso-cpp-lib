/**************************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/                        *
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

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "CommonTransactionManager.h"

/* Calypsonet Terminal Reader */
#include "SmartCard.h"

/* Keyple Card Calypso */
#include "CommonSecuritySettingAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;
using namespace calypsonet::terminal::reader::selection::spi;
/**
 * (package-private)<br>
 * Implementation of {@link CommonTransactionManager}.
 *
 * @param <T> The type of the lowest level child object.
 * @param <S> The type of the lowest level child object of the associated {@link
 *     CommonSecuritySetting}.
 * @since 2.2.0
 */
template <typename T, typename S>
class CommonTransactionManagerAdapter : public CommonTransactionManager<T, S> {
public:
    /* Prefix/suffix used to compose exception messages */
    static const std::string MSG_SAM_READER_COMMUNICATION_ERROR;
    static const std::string MSG_SAM_COMMUNICATION_ERROR;
    static const std::string MSG_SAM_COMMAND_ERROR;
    static const std::string MSG_WHILE_TRANSMITTING_COMMANDS;

    /**
     * (package-private)<br>
     * Creates a new instance.
     *
     * @param targetSmartCard The target smartcard provided by the selection process.
     * @param securitySetting The security settings (optional).
     * @param transactionAuditData The original transaction data to fill (optional).
     * @since 2.2.0
     */
    CommonTransactionManagerAdapter(
        std::shared_ptr<SmartCard> targetSmartCard,
        const std::shared_ptr<CommonSecuritySettingAdapter> securitySetting,
        const std::vector<std::vector<uint8_t>>& transactionAuditData);

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::vector<std::vector<uint8_t>>& getTransactionAuditData() const final

    /**
     * (package-private)<br>
     * Creates a list of {@link ApduRequestSpi} from a list of {@link AbstractApduCommand}.
     *
     * @param commands The list of commands.
     * @return An empty list if there is no command.
     * @since 2.2.0
     */
    //final <E extends AbstractApduCommand> List<ApduRequestSpi> getApduRequests(List<E> commands) {
    const std::vector<std::shared_ptr<ApduRequestSpi> getApduRequests(
        const std::vector<std::shared_ptr<AbstractApduCommand>>& commands) final;

    /**
     * (package-private)<br>
     * Saves the provided exchanged APDU commands in the list of transaction audit data.
     *
     * @param cardRequest The card request.
     * @param cardResponse The associated card response.
     * @since 2.1.1
     */
    virtual void saveTransactionAuditData(const std::shared_ptr<CardRequestSpi> cardRequest, 
                                          const std::shared_ptr<CardResponseApi> cardResponse);

    /**
     * (package-private)<br>
     * Saves the provided exchanged APDU commands in the provided list of transaction audit data.
     *
     * @param cardRequest The card request.
     * @param cardResponse The associated card response.
     * @param transactionAuditData The list to complete.
     * @since 2.1.1
     */
    virtual static void saveTransactionAuditData(
        const std::shared_ptr<CardRequestSpi> cardRequest, 
        const std::shared_ptr<CardResponseApi> cardResponse, 
        const std::vector<std::vector<uint8_t>>& transactionAuditData);

    /**
     * (package-private)<br>
     * Returns a string representation of the transaction audit data.
     *
     * @return A not empty string.
     */
    const std::string getTransactionAuditDataAsString() const final;

private:
    /**
     * 
     */
    T& mCurrentInstance = dynamic_cast<T&>(*this);

    /**
     * Target card or SAM
     */
    std::shared_ptr<SmartCard> mTargetSmartCard;
    
    /**
     * 
     */
    std::shared_ptr<CommonSecuritySettingAdapter> mSecuritySetting;

    /**
     * 
     */
    std::vector<std::vector<uint8_t>> mTransactionAuditData;
};

}
}
}

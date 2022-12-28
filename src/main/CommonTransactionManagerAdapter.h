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

#include <cstdint>
#include <memory>
#include <string>
#include <sstream>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "CommonTransactionManager.h"

/* Calypsonet Terminal Reader */
#include "SmartCard.h"

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "CommonSecuritySettingAdapter.h"

/* Keyple Core Util */
#include "HexUtil.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;
using namespace calypsonet::terminal::reader::selection::spi;
using namespace keyple::core::util;

/**
 * (package-private)<br>
 * Implementation of CommonTransactionManager.
 *
 * @param <T> The type of the lowest level child object.
 * @param <S> The type of the lowest level child object of the associated CommonSecuritySetting.
 * @param <U> (C++ only) The type of CommonSecuritySettingAdapter child object
 * @since 2.2.0
 */
template <typename T, typename S, typename U>
class CommonTransactionManagerAdapter
: virtual public CommonTransactionManager<T, S> {
public:
    /* Prefix/suffix used to compose exception messages */
    const std::string MSG_SAM_READER_COMMUNICATION_ERROR =
        "A communication error with the SAM reader occurred ";
    const std::string MSG_SAM_COMMUNICATION_ERROR =
        "A communication error with the SAM occurred ";
    const std::string MSG_SAM_COMMAND_ERROR =
        "A SAM command error occurred ";
    const std::string MSG_WHILE_TRANSMITTING_COMMANDS =
        "while transmitting commands.";

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
      const std::shared_ptr<CommonSecuritySettingAdapter<U>> securitySetting,
      const std::vector<std::vector<uint8_t>>& transactionAuditData)
    : mTargetSmartCard(targetSmartCard),
      mSecuritySetting(securitySetting),
      mTransactionAuditData(transactionAuditData) {}

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::vector<std::vector<uint8_t>>& getTransactionAuditData() const override
    {
        /* CL-CSS-INFODATA.1 */
        return mTransactionAuditData;
    }

    /**
     * (package-private)<br>
     * Creates a list of ApduRequestSpi from a list of AbstractApduCommand.
     *
     * @param commands The list of commands.
     * @return An empty list if there is no command.
     * @since 2.2.0
     */
    //final <E extends AbstractApduCommand> List<ApduRequestSpi> getApduRequests(List<E> commands) {
    const std::vector<std::shared_ptr<ApduRequestSpi>> getApduRequests(
        const std::vector<std::shared_ptr<AbstractApduCommand>>& commands)
    {
        std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests;

        for (const auto& command : commands) {
            apduRequests.push_back(command->getApduRequest());
        }

        return apduRequests;
    }

    /**
     * (package-private)<br>
     * Saves the provided exchanged APDU commands in the list of transaction audit data.
     *
     * @param cardRequest The card request.
     * @param cardResponse The associated card response.
     * @since 2.1.1
     */
    virtual void saveTransactionAuditData(const std::shared_ptr<CardRequestSpi> cardRequest,
                                          const std::shared_ptr<CardResponseApi> cardResponse)
    {
        if (cardResponse != nullptr) {
            const std::vector<std::shared_ptr<ApduRequestSpi>>& requests =
                cardRequest->getApduRequests();
            const std::vector<std::shared_ptr<ApduResponseApi>>& responses =
                cardResponse->getApduResponses();

            for (int i = 0; i < static_cast<int>(responses.size()); i++) {
                mTransactionAuditData.push_back(requests[i]->getApdu());
                mTransactionAuditData.push_back(responses[i]->getApdu());
            }
        }
    }

    /**
     * (package-private)<br>
     * Saves the provided exchanged APDU commands in the provided list of transaction audit data.
     *
     * @param cardRequest The card request.
     * @param cardResponse The associated card response.
     * @param transactionAuditData The list to complete.
     * @since 2.1.1
     */
    static void saveTransactionAuditData(
        const std::shared_ptr<CardRequestSpi> cardRequest,
        const std::shared_ptr<CardResponseApi> cardResponse,
        std::vector<std::vector<uint8_t>>& transactionAuditData)
    {
        if (cardResponse != nullptr) {
            const std::vector<std::shared_ptr<ApduRequestSpi>>& requests =
                cardRequest->getApduRequests();
            const std::vector<std::shared_ptr<ApduResponseApi>>& responses =
                cardResponse->getApduResponses();

            for (int i = 0; i < static_cast<int>(responses.size()); i++) {
                transactionAuditData.push_back(requests[i]->getApdu());
                transactionAuditData.push_back(responses[i]->getApdu());
            }
        }
    }

    /**
     * (package-private)<br>
     * Returns a string representation of the transaction audit data.
     *
     * @return A not empty string.
     */
    const std::string getTransactionAuditDataAsString() const
    {
        std::stringstream ss;

        ss << "\nTransaction audit JSON data: {";
        ss << "\"targetSmartCard\":" << mTargetSmartCard << ",";

        if (mSecuritySetting != nullptr && mSecuritySetting->getControlSam() != nullptr) {
            ss << "\"controlSam\":" << mSecuritySetting->getControlSam() << ",";
        }

        ss << "\"apdus\": {";
        for(auto it = mTransactionAuditData.begin(); it != mTransactionAuditData.end(); it++) {
            ss << HexUtil::toHex(*it);
            if (it != mTransactionAuditData.end() - 1) {
                ss << ", ";
            }
        }
        ss << "}";

        return ss.str();
    }

private:
    /**
     * Target card or SAM
     */
    std::shared_ptr<SmartCard> mTargetSmartCard;

    /**
     *
     */
    std::shared_ptr<CommonSecuritySettingAdapter<U>> mSecuritySetting;

    /**
     *
     */
    std::vector<std::vector<uint8_t>> mTransactionAuditData;
};

}
}
}

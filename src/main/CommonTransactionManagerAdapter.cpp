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

#include "CommonTransactionManagerAdapter.h"

#include <sstream>

/* Keyple Core Util */
#include "HexUtil.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;

const std::string CommonTransactionManagerAdapter::MSG_SAM_READER_COMMUNICATION_ERROR =
    "A communication error with the SAM reader occurred ";
const std::string CommonTransactionManagerAdapter::MSG_SAM_COMMUNICATION_ERROR =
    "A communication error with the SAM occurred ";
const std::string CommonTransactionManagerAdapter::MSG_SAM_COMMAND_ERROR = 
    "A SAM command error occurred ";
const std::string CommonTransactionManagerAdapter::MSG_WHILE_TRANSMITTING_COMMANDS = 
    "while transmitting commands.";

CommonTransactionManagerAdapter::CommonTransactionManagerAdapter(
  std::shared_ptr<SmartCard> targetSmartCard,
  const std::shared_ptr<CommonSecuritySettingAdapter> securitySetting,
  const std::vector<std::vector<uint8_t>>& transactionAuditData)
: mTargetSmartCard(targetSmartCard),
  mSecuritySetting(securitySetting),
  mTransactionAuditData(transactionAuditData) {}

const std::vector<std::vector<uint8_t>>& CommonTransactionManagerAdapter::getTransactionAuditData() 
    const
{
    /* CL-CSS-INFODATA.1 */
    return mTransactionAuditData;
}

const std::vector<std::shared_ptr<ApduRequestSpi> CommonTransactionManagerAdapter::getApduRequests(
    const std::vector<std::shared_ptr<AbstractApduCommand>>& commands)
{
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests;

    for (const auto& command : commands) {
        apduRequests.push_back(command->getApduRequest());
    }
    
    return apduRequests;
}

void CommonTransactionManagerAdapter::saveTransactionAuditData(
    const std::shared_ptr<CardRequestSpi> cardRequest, 
    const std::shared_ptr<CardResponseApi> cardResponse) 
{
    if (cardResponse != nullptr) {
        const std::vector<std::shared_ptr<ApduRequestSpi>>& requests = 
            cardRequest.getApduRequests();
        const std::vector<std::shared_ptr<ApduResponseApi>>& responses = 
            cardResponse.getApduResponses();
        
        for (int i = 0; i < static_cast<int>(responses.size()); i++) {
            mTransactionAuditData.push_back(requests[i]->getApdu());
            mTransactionAuditData.push_back(responses[i]->getApdu());
        }
    }
}

void CommonTransactionManagerAdapter::saveTransactionAuditData(
    const std::shared_ptr<CardRequestSpi> cardRequest, 
    const std::shared_ptr<CardResponseApi> cardResponse, 
    const std::vector<std::vector<uint8_t>>& transactionAuditData) 
{
    if (cardResponse != nullptr) {
        const std::vector<std::shared_ptr<ApduRequestSpi>>& requests = 
            cardRequest.getApduRequests();
        const std::vector<std::shared_ptr<ApduResponseApi>>& responses = 
            cardResponse.getApduResponses();

        for (int i = 0; i < static_cast<int>(responses.size()); i++) {
            transactionAuditData.push_back(requests[i]->getApdu());
            transactionAuditData.push_back(responses[i]->getApdu());
        }
    }
}

const std::string CommonTransactionManagerAdapter::getTransactionAuditDataAsString() const 
{
    std::stringstream ss;

    ss << "\nTransaction audit JSON data: {";
    ss << "\"targetSmartCard\":" << mTargetSmartCard << ",";
    
    if (mSecuritySetting != nullptr && mSecuritySetting->getControlSam() != nullptr) {
        ss << "\"controlSam\":" << mSecuritySetting->getControlSam() << ",";
    }

    ss << "\"apdus\": {";
    for(int i = 0, auto it = mTransactionAuditData.begin(); it != mTransactionAuditData.end(); it++, i++ ) {
        ss << HexUtil::toHex(mTransactionAuditData[i];
        if (it != mTransactionAuditData.end() - 1) {
            ss << ", ";
        }
    }
    ss << "}";
    
    return ss.str();
}


}
}
}

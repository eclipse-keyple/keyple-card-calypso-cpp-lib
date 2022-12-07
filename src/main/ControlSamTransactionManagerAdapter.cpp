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

#include "ControlSamTransactionManagerAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

ControlSamTransactionManagerAdapter::ControlSamTransactionManagerAdapter(
  const std::shared_ptr<CalypsoCardAdapter> targetCard,
  const std::shared_ptr<CardSecuritySettingAdapter> securitySetting,
  const std::vector<uint8_t>& defaultKeyDiversifier,
  const std::vector<std::vector<uint8_t>>& transactionAuditData)
: CommonSamTransactionManagerAdapter(targetCard, 
                                     securitySetting, 
                                     defaultKeyDiversifier, 
                                     transactionAuditData),
  mTargetCard(targetCard),
  mCardSecuritySetting(securitySetting)
  mTargetSam(nullptr),
  mSamSecuritySetting(nullptr) {}

ControlSamTransactionManagerAdapter::ControlSamTransactionManagerAdapter(
  const std::shared_ptr<CalypsoSamAdapter> targetSam,
  const std::shared_ptr<SamSecuritySettingAdapter> securitySetting,
  const std::vector<uint8_t>& defaultKeyDiversifier,
  const std::vector<std::vector<uint8_t>>& transactionAuditData)
: CommonSamTransactionManagerAdapter(targetSam, 
                                     securitySetting, 
                                     defaultKeyDiversifier, 
                                     transactionAuditData),
  mTargetCard(nullptr),
  mCardSecuritySetting(nullptr),
  mTargetSam(targetSam),
  mSamSecuritySetting(securitySetting) {}

const std::shared_ptr<SamSecuritySetting> ControlSamTransactionManagerAdapter::getSecuritySetting()
{
    /* No security settings for a control SAM */
    return nullptr;
}

}
}
}

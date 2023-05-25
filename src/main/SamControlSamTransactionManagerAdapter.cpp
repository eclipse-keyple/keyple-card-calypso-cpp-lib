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

#include "SamControlSamTransactionManagerAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

SamControlSamTransactionManagerAdapter::SamControlSamTransactionManagerAdapter(
  const std::shared_ptr<CalypsoSamAdapter> targetSam,
  const std::shared_ptr<SamSecuritySettingAdapter> securitySetting,
  const std::vector<std::vector<uint8_t>>& transactionAuditData)
: CommonControlSamTransactionManagerAdapter(
      targetSam,
      securitySetting,
      targetSam ? targetSam->getSerialNumber() : std::vector<uint8_t>(),
      transactionAuditData),
  mControlSam(securitySetting ? securitySetting->getControlSam() : nullptr),
  mTargetSam(targetSam),
  mSamSecuritySetting(securitySetting) {}

}
}
}

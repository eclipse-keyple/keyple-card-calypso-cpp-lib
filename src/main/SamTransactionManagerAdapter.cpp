/**************************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#include "SamTransactionManagerAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

const int SamTransactionManagerAdapter::MIN_EVENT_COUNTER_NUMBER = 0;
const int SamTransactionManagerAdapter::MAX_EVENT_COUNTER_NUMBER = 26;
const int SamTransactionManagerAdapter::MIN_EVENT_CEILING_NUMBER = 0;
const int SamTransactionManagerAdapter::MAX_EVENT_CEILING_NUMBER = 26;
const int SamTransactionManagerAdapter::FIRST_COUNTER_REC1 = 0;
const int SamTransactionManagerAdapter::LAST_COUNTER_REC1 = 8;
const int SamTransactionManagerAdapter::FIRST_COUNTER_REC2 = 9;
const int SamTransactionManagerAdapter::LAST_COUNTER_REC2 = 17;
const int SamTransactionManagerAdapter::FIRST_COUNTER_REC3 = 18;
const int SamTransactionManagerAdapter::LAST_COUNTER_REC3 = 26;

SamTransactionManagerAdapter::SamTransactionManagerAdapter(
  const std::shared_ptr<ProxyReaderApi> samReader,
  const std::shared_ptr<CalypsoSamAdapter> sam,
  const std::shared_ptr<SamSecuritySettingAdapter> securitySetting)
: CommonSamTransactionManagerAdapter(samReader, sam, securitySetting),
  mSecuritySetting(securitySetting),
  mControlSamTransactionManager(securitySetting != nullptr &&
                                securitySetting->getControlSam() != nullptr ?
                                std::make_shared<SamControlSamTransactionManagerAdapter>(
                                    sam,
                                    securitySetting,
                                    getTransactionAuditData()) : nullptr) {}

const std::shared_ptr<CommonSecuritySetting> SamTransactionManagerAdapter::getSecuritySetting() const
{
    return mSecuritySetting;
}

}
}
}

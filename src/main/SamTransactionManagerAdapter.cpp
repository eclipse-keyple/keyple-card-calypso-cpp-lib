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

#include "SamTransactionManagerAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

SamTransactionManagerAdapter::SamTransactionManagerAdapter(
  const std::shared_ptr<ProxyReaderApi> samReader, 
  const std::shared_ptr<CalypsoSamAdapter> sam, 
  const std::shared_ptr<SamSecuritySettingAdapter> securitySetting)
: CommonSamTransactionManagerAdapter(samReader, sam, securitySetting),
  mSecuritySetting(securitySetting),
  mControlSamTransactionManager(securitySetting != nullptr && 
                                securitySetting->getControlSam() != nullptr ?
                                std::make_shared<ControlSamTransactionManagerAdapter>(
                                    sam, 
                                    securitySetting, 
                                    sam->getSerialNumber(), 
                                    getTransactionAuditData()) : nullptr) {}

const std::shared_ptr<SamSecuritySetting> SamTransactionManagerAdapter::getSecuritySetting() const 
{
    return mSecuritySetting;
}

}
}
}

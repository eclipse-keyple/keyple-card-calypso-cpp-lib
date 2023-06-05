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

/* Keyple Card Calypso */
#include "CalypsoSamAdapter.h"
#include "CommonControlSamTransactionManagerAdapter.h"
#include "SamSecuritySettingAdapter.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util::cpp;

/**
 * (package-private)<br>
 * Control SAM Transaction Manager.
 *
 *
 * @since 2.2.0
 */
class SamControlSamTransactionManagerAdapter final :
public CommonControlSamTransactionManagerAdapter<CommonSecuritySetting> {
public:
    /**
     * (package-private)<br>
     * Creates a new instance to control a SAM.
     *
     * @param targetSam The target SAM to control provided by the selection process.
     * @param securitySetting The associated SAM security settings.
     * @param transactionAuditData The original transaction data to fill.
     * @since 2.2.0
     */
    SamControlSamTransactionManagerAdapter(
        const std::shared_ptr<CalypsoSamAdapter> targetSam,
        const std::shared_ptr<SamSecuritySettingAdapter> securitySetting,
        const std::vector<std::vector<uint8_t>>& transactionAuditData);

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger =
        LoggerFactory::getLogger(typeid(SamControlSamTransactionManagerAdapter));

    /**
     *
     */
    const std::shared_ptr<CalypsoSamAdapter> mControlSam;

    /**
     *
     */
    const std::shared_ptr<CalypsoSamAdapter> mTargetSam;

    /**
     *
     */
    const std::shared_ptr<SamSecuritySettingAdapter> mSamSecuritySetting;

};

}
}
}

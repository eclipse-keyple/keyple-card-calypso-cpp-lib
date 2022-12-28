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

#include <memory>

/* Keyple Card Calypso */
#include "CommonSamTransactionManagerAdapter.h"
#include "CommonSecuritySettingAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Common Control SAM Transaction Manager.
 *
 * @param <T> The type of the lowest level child object of the associated CommonSecuritySettingAdapter.
 *
 * @since 2.2.0
 */
template <typename T>
class CommonControlSamTransactionManagerAdapter
: public CommonSamTransactionManagerAdapter<T> {
public:
    /**
     * (package-private)<br>
     * Creates a new instance (to be used for instantiation of
     * CommonControlSamTransactionManagerAdapter only).
     *
     * @param targetSmartCard The target smartcard provided by the selection process.
     * @param securitySetting The card or SAM security settings.
     * @param defaultKeyDiversifier The full serial number of the target card or SAM to be used by
     *        default when diversifying keys.
     * @param transactionAuditData The original transaction data to fill.
     * @since 2.2.0
     */
    CommonControlSamTransactionManagerAdapter(
      const std::shared_ptr<SmartCard> targetSmartCard,
      const std::shared_ptr<CommonSecuritySettingAdapter<T>> securitySetting,
      const std::vector<uint8_t>& defaultKeyDiversifier,
      const std::vector<std::vector<uint8_t>>& transactionAuditData)
    : CommonSamTransactionManagerAdapter<T>(targetSmartCard,
                                            securitySetting,
                                            defaultKeyDiversifier,
                                            transactionAuditData) {}

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::shared_ptr<SamSecuritySetting> getSecuritySetting() const override
    {
        /* No security settings for a control SAM. */
        return nullptr;
    }
};

}
}
}

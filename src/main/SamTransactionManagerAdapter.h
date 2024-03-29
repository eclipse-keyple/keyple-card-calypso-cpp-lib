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

#pragma once

/* Keyple Core Util */
#include "LoggerFactory.h"

/* Keyple Card Calypso */
#include "SamControlSamTransactionManagerAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util::cpp;

/**
 * (package-private)<br>
 * Implementation of SamTransactionManager.
 *
 * @since 2.2.0
 */
class SamTransactionManagerAdapter final
: public CommonSamTransactionManagerAdapter<SamSecuritySetting> {
public:
    /**
     * (package-private)<br>
     * Creates a new instance.
     *
     * @param samReader The reader through which the SAM communicates.
     * @param sam The initial SAM data provided by the selection process.
     * @param securitySetting The security settings (optional).
     * @since 2.2.0
     */
    SamTransactionManagerAdapter(const std::shared_ptr<ProxyReaderApi> samReader,
                                 const std::shared_ptr<CalypsoSamAdapter> sam,
                                 const std::shared_ptr<SamSecuritySettingAdapter> securitySetting);

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::shared_ptr<CommonSecuritySetting> getSecuritySetting() const override;

private:

    /**
     * Constants
     */
    static const int MIN_EVENT_COUNTER_NUMBER;
    static const int MAX_EVENT_COUNTER_NUMBER;
    static const int MIN_EVENT_CEILING_NUMBER;
    static const int MAX_EVENT_CEILING_NUMBER;
    static const int FIRST_COUNTER_REC1;
    static const int LAST_COUNTER_REC1;
    static const int FIRST_COUNTER_REC2;
    static const int LAST_COUNTER_REC2;
    static const int FIRST_COUNTER_REC3;
    static const int LAST_COUNTER_REC3;

    /**
     *
     */
    const std::unique_ptr<Logger> mLogger =
        LoggerFactory::getLogger(typeid(SamTransactionManagerAdapter));

    /**
     *
     */
    const std::shared_ptr<SamSecuritySettingAdapter> mSecuritySetting;

    /**
     *
     */
    const std::shared_ptr<SamControlSamTransactionManagerAdapter> mControlSamTransactionManager;
};

}
}
}

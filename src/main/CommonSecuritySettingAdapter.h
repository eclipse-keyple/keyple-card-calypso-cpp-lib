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

/* Calypsonet Terminal Calypso */
#include "CommonSecuritySetting.h"

/* Calypsonet Terminal Card */
#include "ProxyReaderApi.h"

/* Keyple Card Calypso */
#include "CalypsoSamAdapter.h"

/* Keple Core Util */
#include "IllegalArgumentException.h"
#include "KeypleAssert.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;
using namespace calypsonet::terminal::card;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

/**
 * (package-private)<br>
 * Implementation of CommonSecuritySetting.
 *
 * @param <S> The type of the lowest level child object.
 * @since 2.2.0
 */
template <typename S>
class CommonSecuritySettingAdapter : virtual public CommonSecuritySetting<S> {
public:
    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    S& setControlSamResource(const std::shared_ptr<CardReader> samReader,
                             const std::shared_ptr<CalypsoSam> calypsoSam) final
    {
        Assert::getInstance().notNull(samReader, "samReader")
                            .notNull(calypsoSam, "calypsoSam");

        Assert::getInstance().isTrue(calypsoSam->getProductType() != CalypsoSam::ProductType::UNKNOWN,
                                    "productType");

        auto proxy = std::dynamic_pointer_cast<ProxyReaderApi>(samReader);
        if (!proxy) {
            throw IllegalArgumentException("The provided 'samReader' must implement 'ProxyReaderApi'");
        }

        auto adapter = std::dynamic_pointer_cast<CalypsoSamAdapter>(calypsoSam);
        if (!adapter) {
            throw IllegalArgumentException("The provided 'calypsoSam' must be an instance of " \
                                        "'CalypsoSamAdapter'");
        }

        mControlSamReader = std::dynamic_pointer_cast<ProxyReaderApi>(samReader);
        mControlSam = std::dynamic_pointer_cast<CalypsoSamAdapter>(calypsoSam);

        return *mCurrentInstance;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    S& setSamRevocationService(const std::shared_ptr<SamRevocationServiceSpi> service) final
    {
        Assert::getInstance().notNull(service, "service");

        mSamRevocationServiceSpi = service;

        return *mCurrentInstance;
    }

    /**
     * (package-private)<br>
     * Gets the associated control SAM reader to use for secured operations.
     *
     * @return Null if no control SAM reader is set.
     * @since 2.2.0
     */
    std::shared_ptr<ProxyReaderApi> getControlSamReader() const
    {
        return mControlSamReader;
    }

    /**
     * (package-private)<br>
     * Gets the control SAM used for secured operations.
     *
     * @return Null if no control SAM is set.
     * @since 2.2.0
     */
    std::shared_ptr<CalypsoSamAdapter> getControlSam() const
    {
        return mControlSam;
    }

    /**
     * (package-private)<br>
     * Gets the SAM revocation service.
     *
     * @return Null if no SAM revocation service is set.
     * @since 2.2.0
     */
    std::shared_ptr<SamRevocationServiceSpi> getSamRevocationServiceSpi() const
    {
        return mSamRevocationServiceSpi;
    }

private:
    /**
     *
     */
    S* mCurrentInstance = dynamic_cast<S*>(this);

    /**
     *
     */
    std::shared_ptr<ProxyReaderApi> mControlSamReader;

    /**
     *
     */
    std::shared_ptr<CalypsoSamAdapter> mControlSam;

    /**
     *
     */
    std::shared_ptr<SamRevocationServiceSpi> mSamRevocationServiceSpi;
};

}
}
}

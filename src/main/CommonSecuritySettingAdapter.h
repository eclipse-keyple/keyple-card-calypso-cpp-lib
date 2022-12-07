/**************************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/                        *
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

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;

/**
 * (package-private)<br>
 * Implementation of {@link CommonSecuritySetting}.
 *
 * @param <S> The type of the lowest level child object.
 * @since 2.2.0
 */
template <typename T>
class CommonSecuritySettingAdapter<CommonSecuritySetting<T>>
: public CommonSecuritySetting<S> {
public:
    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    T& setControlSamResource(const std::shared_ptr<CardReader> samReader, 
                             const std::shared_ptr<CalypsoSam> calypsoSam) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    T& setSamRevocationService(const std::shared_ptr<SamRevocationServiceSpi> service) final;

    /**
     * (package-private)<br>
     * Gets the associated control SAM reader to use for secured operations.
     *
     * @return Null if no control SAM reader is set.
     * @since 2.2.0
     */
    std::shared_ptr<ProxyReaderApi> getControlSamReader() const final;

    /**
     * (package-private)<br>
     * Gets the control SAM used for secured operations.
     *
     * @return Null if no control SAM is set.
     * @since 2.2.0
     */
    std::shared_ptr<CalypsoSamAdapter> getControlSam() const final;

    /**
     * (package-private)<br>
     * Gets the SAM revocation service.
     *
     * @return Null if no SAM revocation service is set.
     * @since 2.2.0
     */
    std::shared_ptr<SamRevocationServiceSpi> getSamRevocationServiceSpi() const final;

private:
    /**
     *
     */
    T& currentInstance = dynamic_cast<T&>(*this);

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

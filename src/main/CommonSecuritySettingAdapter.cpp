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

#include "CommonSecuritySettingAdapter.h"

/* Keple Core Util */
#include "IllegalArgumentException.h"
#include "KeypleAssert.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

T& CommonSecuritySettingAdapter::setControlSamResource(
    const std::shared_ptr<CardReader> samReader, 
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

    mControlSamReader = samReader;
    mControlSam = calypsoSam;

    return mCurrentInstance;
}

T& CommonSecuritySettingAdapter::setSamRevocationService(
    const std::shared_ptr<SamRevocationServiceSpi> service)
{
    Assert::getInstance().notNull(service, "service");
    
    mSamRevocationServiceSpi = service;
    
    return mCurrentInstance;
}

std::shared_ptr<ProxyReaderApi> CommonSecuritySettingAdapter::getControlSamReader() const
{
    return mControlSamReader;
}

std::shared_ptr<CalypsoSamAdapter> CommonSecuritySettingAdapter::getControlSam() const
{
    return mControlSam;
}

std::shared_ptr<SamRevocationServiceSpi> CommonSecuritySettingAdapter::getSamRevocationServiceSpi()
    const
{
    return mSamRevocationServiceSpi;
}

}
}
}

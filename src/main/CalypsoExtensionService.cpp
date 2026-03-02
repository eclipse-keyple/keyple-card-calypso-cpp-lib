/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * See the NOTICE file(s) distributed with this work for additional           *
 * information regarding copyright ownership.                                 *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the Eclipse Public License 2.0 which is available at              *
 * http://www.eclipse.org/legal/epl-2.0                                       *
 *                                                                            *
 * SPDX-License-Identifier: EPL-2.0                                           *
 ******************************************************************************/

#include "keyple/card/calypso/CalypsoExtensionService.hpp"

#include "keyple/card/calypso/CalypsoCardApiFactoryAdapter.hpp"
#include "keyple/core/common/CommonApiProperties.hpp"
#include "keypop/card/CardApiProperties.hpp"
#include "keypop/reader/ReaderApiProperties.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::common::CommonApiProperties_VERSION;
using keypop::card::CardApiProperties_VERSION;
using keypop::reader::ReaderApiProperties_VERSION;

std::shared_ptr<CalypsoExtensionService> CalypsoExtensionService::mInstance;

std::shared_ptr<CalypsoExtensionService>
CalypsoExtensionService::getInstance()
{
    if (mInstance == nullptr) {
        mInstance = std::shared_ptr<CalypsoExtensionService>(
            new CalypsoExtensionService());
    }

    return mInstance;
}

std::shared_ptr<CalypsoCardApiFactory>
CalypsoExtensionService::getCalypsoCardApiFactory()
{
    return std::make_shared<CalypsoCardApiFactoryAdapter>();
}

const std::string
CalypsoExtensionService::getReaderApiVersion() const
{
    return ReaderApiProperties_VERSION;
}

const std::string
CalypsoExtensionService::getCardApiVersion() const
{
    return CardApiProperties_VERSION;
}

const std::string
CalypsoExtensionService::getCommonApiVersion() const
{
    return CommonApiProperties_VERSION;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */

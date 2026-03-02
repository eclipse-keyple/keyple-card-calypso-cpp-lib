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

#pragma once

#include <memory>
#include <string>

#include "keyple/card/calypso/KeypleCardCalypsoExport.hpp"
#include "keyple/core/common/KeypleCardExtension.hpp"
#include "keypop/calypso/card/CalypsoCardApiFactory.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::common::KeypleCardExtension;
using keypop::calypso::card::CalypsoCardApiFactory;

/**
 * Card extension dedicated to the management of Calypso cards.
 *
 * @since 2.0.0
 */
class KEYPLECARDCALYPSO_API CalypsoExtensionService final
: public KeypleCardExtension {
public:
    /**
     * Returns the service instance.
     *
     * @return A not null reference.
     * @since 2.0.0
     */
    static std::shared_ptr<CalypsoExtensionService> getInstance();

    /**
     * Returns new instance of CalypsoCardApiFactory.
     *
     * @return A not null reference.
     * @since 3.0.0
     */
    std::shared_ptr<CalypsoCardApiFactory> getCalypsoCardApiFactory();

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::string getReaderApiVersion() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::string getCardApiVersion() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::string getCommonApiVersion() const override;

private:
    /**
     * Singleton instance of CalypsoExtensionService
     */
    static std::shared_ptr<CalypsoExtensionService> mInstance;
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */

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

#include <memory>

/* Calypsonet Terminal Calypso */
#include "CalypsoSamSelection.h"

/* Keyple Core Service */
#include "CardResourceProfileExtension.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::sam;
using namespace keyple::core::service::resource::spi;
using namespace keyple::core::util::cpp;

/**
 * (package-private)<br>
 * Implementation of CardResourceProfileExtension dedicated to SAM identification.
 *
 * @since 2.0.0
 */
class CalypsoSamResourceProfileExtensionAdapter : public CardResourceProfileExtension {
public:
    /**
     * (package-private)<br>
     *
     * @param calypsoSamSelection The CalypsoSamSelection.
     * @since 2.0.0
     */
    CalypsoSamResourceProfileExtensionAdapter(
        const std::shared_ptr<CalypsoSamSelection> calypsoSamSelection);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    std::shared_ptr<SmartCard> matches(
        std::shared_ptr<CardReader> reader,
        std::shared_ptr<CardSelectionManager> samCardSelectionManager) override;

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger =
        LoggerFactory::getLogger(typeid(CalypsoSamResourceProfileExtensionAdapter));

    /**
     *
     */
    const std::shared_ptr<CalypsoSamSelection> mCalypsoSamSelection;
};

}
}
}

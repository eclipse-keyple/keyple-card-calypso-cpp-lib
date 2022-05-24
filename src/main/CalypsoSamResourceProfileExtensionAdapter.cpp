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

#include "CalypsoSamResourceProfileExtensionAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

CalypsoSamResourceProfileExtensionAdapter::CalypsoSamResourceProfileExtensionAdapter(
  const std::shared_ptr<CalypsoSamSelection> calypsoSamSelection)
: mCalypsoSamSelection(calypsoSamSelection) {}

std::shared_ptr<SmartCard> CalypsoSamResourceProfileExtensionAdapter::matches(
    std::shared_ptr<CardReader> reader,
    std::shared_ptr<CardSelectionManager> samCardSelectionManager)
{

    if (!reader->isCardPresent()) {
        return nullptr;
    }

    samCardSelectionManager->prepareSelection(mCalypsoSamSelection);
    std::shared_ptr<CardSelectionResult> samCardSelectionResult = nullptr;

    try {
        samCardSelectionResult = samCardSelectionManager->processCardSelectionScenario(reader);
    } catch (const Exception& e) {
        mLogger->warn("An exception occurred while selecting the SAM: '%'\n", e.getMessage(), e);
    }

    if (samCardSelectionResult != nullptr) {
        return samCardSelectionResult->getActiveSmartCard();
    }

    return nullptr;
}

}
}
}

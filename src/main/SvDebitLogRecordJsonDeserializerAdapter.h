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
#include "SvDebitLogRecordAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Deserializer of a SvDebitLogRecord.
 *
 * @since 2.0.0
 */
class SvDebitLogRecordJsonDeserializerAdapter final {
    //implements JsonDeserializer<SvDebitLogRecordAdapter>

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    std::shared_ptr<SvDebitLogRecordAdapter> deserialize();
    //     JsonElement json, Type typeOfT, JsonDeserializationContext context)
    //     throws JsonParseException {
    //     return context.deserialize(json, SvDebitLogRecordAdapter.class);
    // }
};

}
}
}

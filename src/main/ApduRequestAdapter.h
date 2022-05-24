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
#include <ostream>
#include <vector>

/* Calypsonet Terminal Card */
#include "ApduRequestSpi.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::card::spi;

/**
 * (package-private)<br>
 * This POJO contains a set of data related to an ISO-7816 APDU command.
 *
 * <ul>
 *   <li>A byte array containing the raw APDU data.
 *   <li>A flag indicating if the APDU is of type 4 (ingoing and outgoing data).
 *   <li>An optional set of integers corresponding to valid status words in response to this APDU.
 * </ul>
 *
 * Attaching an optional name to the request facilitates the enhancement of the application logs
 * using the toString method.
 *
 * @since 2.0.0
 */
class ApduRequestAdapter final : public ApduRequestSpi {
public:
    /**
     * Builds an APDU request from a raw byte buffer.
     *
     * <p>The default status words list is initialized with the standard successful code 9000h.
     *
     * @param apdu The bytes of the APDU's body.
     * @since 2.0.0
     */
    ApduRequestAdapter(const std::vector<uint8_t>& apdu);

    /**
     * Adds a status word to the list of those that should be considered successful for the APDU.
     *
     * <p>Note: initially, the list contains the standard successful status word {@code 9000h}.
     *
     * @param successfulStatusWord A positive int &le; {@code FFFFh}.
     * @return The object instance.
     * @since 2.0.0
     */
    ApduRequestAdapter& addSuccessfulStatusWord(const int successfulStatusWord);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<int>& getSuccessfulStatusWords() const override;

    /**
     * Names the APDU request.
     *
     * <p>This string is dedicated to improve the readability of logs and should therefore only be
     * invoked conditionally (e.g. when log level &gt;= debug).
     *
     * @param info The request name (free text).
     * @return The object instance.
     * @since 2.0.0
     */
    ApduRequestAdapter& setInfo(const std::string& info);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::string& getInfo() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getApdu() const override;

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os,
                                    const std::shared_ptr<ApduRequestAdapter> ara);

private:
    /**
     *
     */
    static const int DEFAULT_SUCCESSFUL_CODE;

    /**
     *
     */
    const std::vector<uint8_t> mApdu;

    /**
     *
     */
    std::vector<int> mSuccessfulStatusWords;

    /**
     *
     */
    std::string mInfo;
};

}
}
}

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

#include <cstdint>
#include <vector>

/* Calypsonet Terminal Card */
#include "CardSelectorSpi.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::card::spi;

using FileOccurrence = CardSelectorSpi::FileOccurrence;
using FileControlInformation = CardSelectorSpi::FileControlInformation;

/**
 * (package-private)<br>
 * Implementation of CardSelectorSpi.
 *
 * @since 2.0.0
 */
class CardSelectorAdapter final : public CardSelectorSpi {
public:
    /**
     * (package-private)<br>
     * Created an instance of CardSelectorAdapter.
     *
     * <p>Initialize default values.
     *
     * @since 2.0.0
     */
    CardSelectorAdapter();

    /**
     * Sets a protocol-based filtering by defining an expected card.
     *
     * <p>If the card protocol is set, only cards using that protocol will match the card selector.
     *
     * @param cardProtocol A not empty String.
     * @return The object instance.
     * @since 2.0.0
     */
    CardSelectorSpi& filterByCardProtocol(const std::string& cardProtocol);

    /**
     * Sets a power-on data-based filtering by defining a regular expression that will be applied to
     * the card's power-on data.
     *
     * <p>If it is set, only the cards whose power-on data is recognized by the provided regular
     * expression will match the card selector.
     *
     * @param powerOnDataRegex A valid regular expression
     * @return The object instance.
     * @since 2.0.0
     */
    CardSelectorSpi& filterByPowerOnData(const std::string& powerOnDataRegex);

    /**
     * Sets a DF Name-based filtering by defining in a byte array the AID that will be included in
     * the standard SELECT APPLICATION command sent to the card during the selection process.
     *
     * <p>The provided AID can be a right truncated image of the target DF Name (see
     * ISO 7816-4 4.2).
     *
     * @param aid A byte array containing 5 to 16 bytes.
     * @return The object instance.
     * @since 2.0.0
     */
    CardSelectorSpi& filterByDfName(const std::vector<uint8_t>& aid);

    /**
     * Sets a DF Name-based filtering by defining in a hexadecimal string the AID that will be
     * included in the standard SELECT APPLICATION command sent to the card during the selection
     * process.
     *
     * <p>The provided AID can be a right truncated image of the target DF Name (see ISO
     * 7816-4 4.2).
     *
     * @param aid A hexadecimal string representation of 5 to 16 bytes.
     * @return The object instance.
     * @since 2.0.0
     */
    CardSelectorSpi& filterByDfName(const std::string& aid);

    /**
     * Sets the file occurrence mode (see ISO7816-4).
     *
     * <p>The default value is {@link FileOccurrence#FIRST}.
     *
     * @param fileOccurrence The {@link FileOccurrence}.
     * @return The object instance.
     * @since 2.0.0
     */
    CardSelectorSpi& setFileOccurrence(const FileOccurrence fileOccurrence);

    /**
     * Sets the file control mode (see ISO7816-4).
     *
     * <p>The default value is {@link FileControlInformation#FCI}.
     *
     * @param fileControlInformation The {@link FileControlInformation}.
     * @return The object instance.
     * @since 2.0.0
     */
    CardSelectorSpi& setFileControlInformation(const FileControlInformation fileControlInformation);

    /**
     * Adds a status word to the list of those that should be considered successful for the Select
     * Application APDU.
     *
     * <p>Note: initially, the list contains the standard successful status word {@code 9000h}.
     *
     * @param statusWord A positive int &le; {@code FFFFh}.
     * @return The object instance.
     * @since 2.0.0
     */
    CardSelectorSpi& addSuccessfulStatusWord(const int statusWord);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::string& getCardProtocol() const final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::string& getPowerOnDataRegex() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getAid() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    FileOccurrence getFileOccurrence() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    FileControlInformation getFileControlInformation() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<int>& getSuccessfulSelectionStatusWords() const override;

private:
    /**
     *
     */
    static const int DEFAULT_SUCCESSFUL_CODE;

    /**
     *
     */
    std::string mCardProtocol;

    /**
     *
     */
    std::string mPowerOnDataRegex;

    /**
     *
     */
    std::vector<uint8_t> mAid;

    /**
     *
     */
    FileOccurrence mFileOccurrence;

    /**
     *
     */
    FileControlInformation mFileControlInformation;

    /**
     *
     */
    std::vector<int> mSuccessfulSelectionStatusWords;
};

}
}
}

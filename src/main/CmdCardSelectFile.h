/**************************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/                        *
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
#include <map>
#include <memory>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "SelectFileControl.h"
#include "CalypsoCard.h"

/* Calypsonet Terminal Cardf */
#include "ApduResponseApi.h"

/* Keyple Card Calypso */
#include "AbstractCardCommand.h"
#include "CalypsoCardAdapter.h"
#include "CalypsoCardClass.h"
#include "CalypsoCardCommand.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::card;
using namespace calypsonet::terminal::calypso;
using namespace calypsonet::terminal::calypso::card;
using namespace keyple::core::util::cpp;

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the Select File APDU commands.
 *
 * <p>The value of the Proprietary Information tag is extracted from the Select File response and
 * made available using the corresponding getter.
 *
 * @since 2.0.1
 */
class CmdCardSelectFile final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdCardSelectFile to select the first, next or current file in the current
     * DF.
     *
     * @param calypsoCard The Calypso card.
     * @param selectFileControl the selection mode control: FIRST, NEXT or CURRENT.
     * @since 2.2.3
     */
    CmdCardSelectFile(const std::shared_ptr<CalypsoCardAdapter> calypsoCard,
                      const SelectFileControl selectFileControl);

    /**
     * (package-private)<br>
     * Instantiates a new CmdCardSelectFile to select the first, next or current file in the current
     * DF.
     *
     * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
     * @param selectFileControl the selection mode control: FIRST, NEXT or CURRENT.
     * @since 2.0.1
     */
    CmdCardSelectFile(const CalypsoCardClass calypsoCardClass,
                      const SelectFileControl selectFileControl);

    /**
     * (package-private)<br>
     * Instantiates a new CmdCardSelectFile to select the first, next or current file in the current
     * DF.
     *
     * @param calypsoCard The Calypso card.
     * @param lid The LID.
     * @since 2.2.3
     */
    CmdCardSelectFile(const std::shared_ptr<CalypsoCardAdapter> calypsoCard, const uint16_t lid);

    /**
     * (package-private)<br>
     * Instantiates a new CmdCardSelectFile to select the first, next or current file in the current
     * DF.
     *
     * @param calypsoCardClass Indicates which CLA byte should be used for the Apdu.
     * @param productType The target product type.
     * @param lid The LID.
     * @since 2.0.1
     */
    CmdCardSelectFile(const CalypsoCardClass calypsoCardClass,
                      const CalypsoCard::ProductType productType,
                      const uint16_t lid);


    /**
     * {@inheritDoc}
     *
     * @since 2.2.3
     */
    void parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * (package-private)<br>
     * Parses the proprietary information and updates the corresponding Calypso card.
     *
     * @param dataOut The dataOut block to parse.
     * @param calypsoCard The Calypso card to update.
     * @since 2.2.3
     */
    static void parseProprietaryInformation(const std::vector<uint8_t>& dataOut,
                                            const std::shared_ptr<CalypsoCardAdapter> calypsoCard);

    /**
     * {@inheritDoc}
     *
     * @return False
     * @since 2.0.1
     */
    bool isSessionBufferUsed() const override;

    /**
     * (package-private)<br>
     *
     * @return The content of the proprietary information tag present in the response to the Select
     *         File command
     */
    static const std::vector<uint8_t> getProprietaryInformation(
        const std::vector<uint8_t>& dataOut);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

private:
    /**
     *
     */
    const std::shared_ptr<Logger> mLogger = LoggerFactory::getLogger(typeid(CmdCardSelectFile));

    /**
     *
     */
    static const CalypsoCardCommand mCommand;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    static const int TAG_PROPRIETARY_INFORMATION;

    /**
     *
     */
    std::vector<uint8_t> mProprietaryInformation;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();

    /**
     * (private)<br>
     * Builds the command.
     *
     * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
     * @param selectFileControl the selection mode control: FIRST, NEXT or CURRENT.
     */
    void buildCommand(const CalypsoCardClass calypsoCardClass,
                      const SelectFileControl selectFileControl);

    /**
     * (private)<br>
     * Builds the command.
     *
     * @param calypsoCardClass Indicates which CLA byte should be used for the Apdu.
     * @param productType The target product type.
     * @param lid The LID.
     */
    void buildCommand(const CalypsoCardClass calypsoCardClass,
                      const CalypsoCard::ProductType productType,
                      const uint16_t lid);

    /**
     * (private)<br>
     * Parses the proprietaryInformation field of a file identified as an DF and create a {@link
     * DirectoryHeader}
     *
     * @param proprietaryInformation from the response to a Select File command.
     * @return A DirectoryHeader object
     */
    static const std::shared_ptr<DirectoryHeader> createDirectoryHeader(
        const std::vector<uint8_t>& proprietaryInformation);

    /**
     * (private)<br>
     * Parses the proprietaryInformation field of a file identified as an EF and create a {@link
     * FileHeaderAdapter}
     *
     * @param proprietaryInformation from the response to a Select File command.
     * @return A {@link FileHeaderAdapter} object
     */
    static const std::shared_ptr<FileHeaderAdapter> createFileHeader(
        const std::vector<uint8_t>& proprietaryInformation);

    /**
     * (private)<br>
     * Converts the EF type value from the card into a {@link ElementaryFile.Type} enum
     *
     * @param efType the value returned by the card.
     * @return The corresponding {@link ElementaryFile.Type}
     */
    static ElementaryFile::Type getEfTypeFromCardValue(const uint8_t efType);
};

}
}
}

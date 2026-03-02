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

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/Command.hpp"
#include "keyple/card/calypso/DtoAdapters.hpp"
#include "keyple/core/util/cpp/Logger.hpp"
#include "keyple/core/util/cpp/LoggerFactory.hpp"
#include "keypop/calypso/card/SelectFileControl.hpp"
#include "keypop/card/ApduResponseApi.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::Logger;
using keyple::core::util::cpp::LoggerFactory;
using keypop::calypso::card::SelectFileControl;
using keypop::card::ApduResponseApi;

/**
 * Builds the Select File APDU commands.
 *
 * <p>The value of the Proprietary Information tag is extracted from the Select
 * File response and made available using the corresponding getter.
 *
 * @since 2.0.1
 */
class CommandSelectFile final : public Command {
public:
    /**
     * Instantiates a new CommandSelectFile to select the first, next or current
     * file in the current DF.
     *
     * @param calypsoCard The Calypso card.
     * @param selectFileControl the selection mode control: FIRST, NEXT or
     * CURRENT.
     * @since 2.3.2
     */
    CommandSelectFile(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        SelectFileControl selectFileControl);

    /**
     * Instantiates a new CommandSelectFile to select the first, next or current
     * file in the current
     * DF.
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @param lid The LID.
     * @since 2.3.2
     */
    CommandSelectFile(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        std::uint16_t lid);

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    void finalizeRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    bool isCryptoServiceRequiredToFinalizeRequest() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    bool synchronizeCryptoServiceBeforeCardProcessing() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<int, const std::shared_ptr<StatusProperties>>&
    getStatusTable() const override;

    /**
     * Parses the proprietary information and updates the corresponding Calypso
     * card.
     *
     * @param dataOut The dataOut block to parse.
     * @param calypsoCard The Calypso card to update.
     * @since 2.2.3
     */
    static void parseProprietaryInformation(
        const std::vector<std::uint8_t>& dataOut,
        std::shared_ptr<CalypsoCardAdapter> calypsoCard);

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger
        = LoggerFactory::getLogger(typeid(CommandSelectFile));

    /**
     *
     */
    static const CardCommandRef mCommandRef;

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<Command::StatusProperties>>
        STATUS_TABLE;

    /**
     *
     */
    static const int TAG_PROPRIETARY_INFORMATION;

    /**
     * @return The content of the proprietary information tag present in the
     * response to the SelectFile command
     */
    static std::vector<std::uint8_t>
    getProprietaryInformation(const std::vector<std::uint8_t>& dataOut);

    /**
     * Parses the proprietaryInformation field of a file identified as an DF and
     * create a DirectoryHeader.
     *
     * @param proprietaryInformation from the response to a Select File command.
     * @param calypsoCard the Calypso card.
     * @return A DirectoryHeader object
     */
    static std::unique_ptr<DirectoryHeader> createDirectoryHeader(
        const std::vector<std::uint8_t>& proprietaryInformation,
        const std::shared_ptr<CalypsoCardAdapter>& calypsoCard);

    /**
     * Parses the proprietaryInformation field of a file identified as an EF and
     * create a FileHeaderAdapter.
     *
     * @param proprietaryInformation from the response to a Select File command.
     * @param calypsoCard the Calypso card.
     * @return A FileHeaderAdapter object
     */
    static std::shared_ptr<FileHeaderAdapter> createFileHeader(
        const std::vector<std::uint8_t>& proprietaryInformation,
        const std::shared_ptr<CalypsoCardAdapter>& calypsoCard);

    /**
     * Converts the EF type value from the card into a ElementaryFile::Type enum
     *
     * @param efType the value returned by the card.
     * @return The corresponding {@link ElementaryFile.Type}
     */
    static ElementaryFile::Type getEfTypeFromCardValue(std::uint8_t efType);
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */

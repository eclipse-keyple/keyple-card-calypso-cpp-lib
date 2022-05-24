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
#include <string>

/* Calypsonet Terminal Calypso */
#include "CalypsoCard.h"
#include "CalypsoCardSelection.h"
#include "CalypsoSamSelection.h"
#include "CardSecuritySetting.h"
#include "CardTransactionManager.h"
#include "SearchCommandData.h"

/* Keyple Card Calypso */
#include "CalypsoCardSelectionAdapter.h"
#include "CalypsoSamSelectionAdapter.h"
#include "SearchCommandDataAdapter.h"

/* Keyple Core Common */
#include "KeypleCardExtension.h"

/* Keyple Core Service */
#include "CardResourceProfileExtension.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::card;
using namespace calypsonet::terminal::calypso::sam;
using namespace calypsonet::terminal::calypso::transaction;
using namespace keyple::card::calypso;
using namespace keyple::core::common;
using namespace keyple::core::service::resource::spi;


/**
 * Card extension dedicated to the management of Calypso cards.
 *
 * @since 2.0.0
 */
class CalypsoExtensionService final : public KeypleCardExtension {
public:
    /**
     *
     */
    static const std::string PRODUCT_TYPE;

    // static {
    //     // Register additional JSON adapters.
    //     JsonUtil.registerTypeAdapter(
    //         DirectoryHeader.class, new DirectoryHeaderJsonDeserializerAdapter(), false);
    //     JsonUtil.registerTypeAdapter(
    //         ElementaryFile.class, new ElementaryFileJsonDeserializerAdapter(), false);
    //     JsonUtil.registerTypeAdapter(FileHeader.class, new FileHeaderJsonDeserializerAdapter(), false);
    //     JsonUtil.registerTypeAdapter(
    //         SvLoadLogRecord.class, new SvLoadLogRecordJsonDeserializerAdapter(), false);
    //     JsonUtil.registerTypeAdapter(
    //         SvDebitLogRecord.class, new SvDebitLogRecordJsonDeserializerAdapter(), false);
    // }

    /**
     * Gets the single instance of CalypsoExtensionService.
     *
     * @return The instance of CalypsoExtensionService.
     * @since 2.0.0
     */
    static std::shared_ptr<CalypsoExtensionService> getInstance();

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::string& getReaderApiVersion() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::string& getCardApiVersion() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::string& getCommonApiVersion() const override;

    /**
     * Creates an instance of SearchCommandData to be used to define the parameters of the
     * CardTransactionManager::prepareSearchRecords(SearchCommandData) method.
     *
     * @return A not null reference.
     * @since 2.1.0
     */
    std::shared_ptr<SearchCommandData> createSearchCommandData() const;

    /**
     * Creates an instance of CalypsoCardSelection that can be supplemented later with
     * specific commands.
     *
     * @return A not null reference.
     * @since 2.0.0
     */
    std::shared_ptr<CalypsoCardSelection> createCardSelection() const;

    /**
     * Creates an instance of {@link CalypsoCardSelection}.
     *
     * @return A not null reference.
     * @since 2.0.0
     */
    std::shared_ptr<CalypsoSamSelection> createSamSelection() const;

    /**
     * Creates an instance of CardResourceProfileExtension to be provided to the
     * CardResourceService.
     *
     * <p>The provided argument defines the selection rules to be applied to the SAM when detected by
     * the card resource service.
     *
     * @param calypsoSamSelection A not null CalypsoSamSelection.
     * @return A not null reference.
     * @throw IllegalArgumentException If calypsoSamSelection is null.
     * @since 2.0.0
     */
    std::shared_ptr<CardResourceProfileExtension> createSamResourceProfileExtension(
        const std::shared_ptr<CalypsoSamSelection> calypsoSamSelection) const;

    /**
     * Creates an instance of CalypsoCardSelection that can be supplemented later with
     * specific commands.
     *
     * @return A not null reference.
     * @since 2.0.0
     */
    std::shared_ptr<CardSecuritySetting> createCardSecuritySetting() const;

    /**
     * Creates a card transaction manager to handle operations secured with a SAM.
     *
     * <p>The reader and the card's initial data are those from the selection.<br>
     * The provided CardSecuritySetting must match the specific needs of the card (SAM card
     * resource profile and other optional settings).
     *
     * @param reader The reader through which the card communicates.
     * @param calypsoCard The initial card data provided by the selection process.
     * @param cardSecuritySetting The security settings.
     * @return A not null reference.
     * @throw IllegalArgumentException If one of the provided argument is null or if the CalypsoCard
     *        has a null or unknown product type.
     * @since 2.0.0
     */
    std::shared_ptr<CardTransactionManager> createCardTransaction(
        std::shared_ptr<CardReader> reader,
        const std::shared_ptr<CalypsoCard> calypsoCard,
        const std::shared_ptr<CardSecuritySetting> cardSecuritySetting);

    /**
     * Creates a card transaction manager to handle non-secured operations.
     *
     * @param reader The reader through which the card communicates.
     * @param calypsoCard The initial card data provided by the selection process.
     * @return A not null reference.
     * @throw IllegalArgumentException If one of the provided argument is null or if the CalypsoCard
     *        has a null or unknown product type.
     * @since 2.0.0
     */
    std::shared_ptr<CardTransactionManager> createCardTransactionWithoutSecurity(
        std::shared_ptr<CardReader> reader, const std::shared_ptr<CalypsoCard> calypsoCard);

private:
    /**
     * Singleton instance of CalypsoExtensionService
     */
    static std::shared_ptr<CalypsoExtensionService> mInstance;


    /**
     * Private constructor
     */
    CalypsoExtensionService();
};

}
}
}

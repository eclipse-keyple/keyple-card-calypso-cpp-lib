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
#include "BasicSignatureComputationData.h"
#include "BasicSignatureVerificationData.h"
#include "CalypsoCard.h"
#include "CalypsoCardSelection.h"
#include "CalypsoSamSelection.h"
#include "CardSecuritySetting.h"
#include "CardTransactionManager.h"
#include "CommonSignatureComputationData.h"
#include "CommonSignatureVerificationData.h"
#include "SamSecuritySetting.h"
#include "SamTransactionManager.h"
#include "SearchCommandData.h"

/* Keyple Card Calypso */
#include "CalypsoCardSelectionAdapter.h"
#include "CalypsoSamSelectionAdapter.h"
#include "CardTransactionManagerAdapter.h"
#include "KeypleCardCalypsoExport.h"
#include "SamTransactionManagerAdapter.h"
#include "SearchCommandDataAdapter.h"
#include "TraceableSignatureComputationData.h"
#include "TraceableSignatureVerificationData.h"

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
using namespace keyple::core::common;
using namespace keyple::core::service::resource::spi;


/**
 * Card extension dedicated to the management of Calypso cards.
 *
 * @since 2.0.0
 */
class KEYPLECARDCALYPSO_API CalypsoExtensionService final : public KeypleCardExtension {
public:
    // static {
    //     // Register additional JSON adapters.
    //     JsonUtil.registerTypeAdapter(ElementaryFile.class, new ElementaryFileJsonAdapter(), false);
    //     JsonUtil.registerTypeAdapter(FileHeader.class, new FileHeaderJsonAdapter(), false);
    //     JsonUtil.registerTypeAdapter(SvLoadLogRecord.class, new SvLoadLogRecordJsonAdapter(), false);
    //     JsonUtil.registerTypeAdapter(SvDebitLogRecord.class, new SvDebitLogRecordJsonAdapter(), false);
    // }

    /**
     * Returns the service instance.
     *
     * @return A not null reference.
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
     * Returns a new instance of SearchCommandData to use to define the parameters of the
     * CardTransactionManager::prepareSearchRecords(SearchCommandData) method.
     *
     * @return A not null reference.
     * @since 2.1.0
     */
    std::shared_ptr<SearchCommandData> createSearchCommandData() const;

    /**
     * Returns a new instance of BasicSignatureComputationData to use to define the parameters
     * of the CardTransactionManager#prepareComputeSignature(CommonSignatureComputationData)
     * and SamTransactionManager#prepareComputeSignature(CommonSignatureComputationData)
     * methods.
     *
     * @return A not null reference.
     * @since 2.2.0
     */
    std::shared_ptr<BasicSignatureComputationData> createBasicSignatureComputationData() const;

    /**
     * Returns a new instance of TraceableSignatureComputationData to use to define the parameters
     * of the CardTransactionManager::prepareComputeSignature(CommonSignatureComputationData) and
     * SamTransactionManager::prepareComputeSignature(CommonSignatureComputationData) methods.
     *
     * @return A not null reference.
     * @since 2.2.0
     */
    std::shared_ptr<TraceableSignatureComputationData> createTraceableSignatureComputationData()
        const;

    /**
     * Returns a new instance of BasicSignatureVerificationData to use to define the parameters of
     * the CardTransactionManager::prepareVerifySignature(CommonSignatureVerificationData) and
     * SamTransactionManager::prepareVerifySignature(CommonSignatureVerificationData) methods.
     *
     * @return A not null reference.
     * @since 2.2.0
     */
    std::shared_ptr<BasicSignatureVerificationData> createBasicSignatureVerificationData() const;

    /**
     * Returns a new instance of TraceableSignatureVerificationData to use to define the parameters
     * of the CardTransactionManager::prepareVerifySignature(CommonSignatureVerificationData) and
     * SamTransactionManager::prepareVerifySignature(CommonSignatureVerificationData) methods.
     *
     * @return A not null reference.
     * @since 2.2.0
     */
    std::shared_ptr<TraceableSignatureVerificationData>
        createTraceableSignatureVerificationData() const;

    /**
     * Creates an instance of CalypsoCardSelection that can be supplemented later with
     * specific commands.
     *
     * @return A not null reference.
     * @since 2.0.0
     */
    std::shared_ptr<CalypsoCardSelection> createCardSelection() const;

    /**
     * Returns a new instance of CalypsoSamSelection to use when selecting a SAM.
     *
     * @return A not null reference.
     * @since 2.0.0
     */
    std::shared_ptr<CalypsoSamSelection> createSamSelection() const;

    /**
     * Returns a new instance of CardResourceProfileExtension to provide to the
     * keyple::core::service::resource::CardResourceService service.
     *
     * <p>The provided argument defines the selection rules to be applied to the SAM when detected
     * by the card resource service.
     *
     * @param calypsoSamSelection A not null CalypsoSamSelection.
     * @return A not null reference.
     * @throw IllegalArgumentException If "calypsoSamSelection" is null.
     * @since 2.0.0
     */
    std::shared_ptr<CardResourceProfileExtension> createSamResourceProfileExtension(
        const std::shared_ptr<CalypsoSamSelection> calypsoSamSelection) const;

    /**
     * Returns a new instance of {@link CardSecuritySetting} to use for secure card operations.
     *
     * @return A not null reference.
     * @since 2.0.0
     */
    std::shared_ptr<CardSecuritySetting> createCardSecuritySetting() const;

    /**
     * Return a new card transaction manager to handle operations secured with a control SAM.
     *
     * <p>The reader and the card's initial data are those from the selection.<br>
     * The provided CardSecuritySetting must match the specific needs of the card (SAM card
     * resource profile and other optional settings).
     *
     * @param cardReader The reader through which the card communicates.
     * @param calypsoCard The initial card data provided by the selection process.
     * @param cardSecuritySetting The security settings.
     * @return A not null reference.
     * @throw IllegalArgumentException If one of the provided argument is null or if "calypsoCard"
     *        has a null or unknown product type.
     * @since 2.0.0
     */
    std::shared_ptr<CardTransactionManager> createCardTransaction(
        std::shared_ptr<CardReader> cardReader,
        const std::shared_ptr<CalypsoCard> calypsoCard,
        const std::shared_ptr<CardSecuritySetting> cardSecuritySetting) const;

    /**
     * Returns a new card transaction manager to handle non-secured operations.
     *
     * @param cardReader The reader through which the card communicates.
     * @param calypsoCard The initial card data provided by the selection process.
     * @return A not null reference.
     * @throw IllegalArgumentException If one of the provided argument is null or if "calypsoCard"
     *        has a null or unknown product type.
     * @since 2.0.0
     */
    std::shared_ptr<CardTransactionManager> createCardTransactionWithoutSecurity(
        std::shared_ptr<CardReader> cardReader,
        const std::shared_ptr<CalypsoCard> calypsoCard) const;

    /**
     * Returns a new instance of SamSecuritySetting to use for secure SAM operations.
     *
     * @return A not null reference.
     * @since 2.2.0
     */
    std::shared_ptr<SamSecuritySetting> createSamSecuritySetting() const;

    /**
     * Returns a new SAM transaction manager to handle operations secured with a control SAM.
     *
     * <p>The reader and the SAM's initial data are those from the selection.<br>
     * The provided SamSecuritySetting must match the specific needs of the SAM (SAM card
     * resource profile and other optional settings).
     *
     * @param samReader The reader through which the SAM communicates.
     * @param calypsoSam The initial SAM data provided by the selection process.
     * @param samSecuritySetting The security settings.
     * @retur A not null reference.
     * @throw IllegalArgumentException If one of the provided argument is null or if "calypsoSam"
     *        has a null or unknown product type.
     * @since 2.2.0
     */
    std::shared_ptr<SamTransactionManager> createSamTransaction(
        std::shared_ptr<CardReader> samReader,
        const std::shared_ptr<CalypsoSam> calypsoSam,
        const std::shared_ptr<SamSecuritySetting> samSecuritySetting) const;

    /**
     * Returns a new SAM transaction manager to handle non-secured operations.
     *
     * @param samReader The reader through which the SAM communicates.
     * @param calypsoSam The initial SAM data provided by the selection process.
     * @return A not null reference.
     * @throw IllegalArgumentException If one of the provided argument is null or if "calypsoSam"
     *        has a null or unknown product type.
     * @since 2.2.0
     */
    std::shared_ptr<SamTransactionManager> createSamTransactionWithoutSecurity(
        std::shared_ptr<CardReader> samReader,
        const std::shared_ptr<CalypsoSam> calypsoSam) const;

private:
    /**
     * Singleton instance of CalypsoExtensionService
     */
    static std::shared_ptr<CalypsoExtensionService> mInstance;


    /**
     * Private constructor
     */
    CalypsoExtensionService();

    /**
     * (private)<br>
     * Returns a new card transaction manager adapter.
     *
     * @param cardReader The reader.
     * @param calypsoCard The card.
     * @param cardSecuritySetting The security settings.
     * @param isSecureMode True if is secure mode requested.
     * @return A not null reference.
     * @throws IllegalArgumentException If one of the provided argument is null or if "calypsoCard"
     *     has a null or unknown product type.
     */
    std::shared_ptr<CardTransactionManagerAdapter> createCardTransactionManagerAdapter(
        std::shared_ptr<CardReader> cardReader,
        const std::shared_ptr<CalypsoCard> calypsoCard,
        const std::shared_ptr<CardSecuritySetting> cardSecuritySetting,
        const bool isSecureMode) const;

    /**
     * (private)<br>
     * Returns a new SAM transaction manager adapter.
     *
     * @param samReader The reader.
     * @param calypsoSam The SAM.
     * @param samSecuritySetting The security settings.
     * @param isSecureMode True if is secure mode requested.
     * @return A not null reference.
     * @throws IllegalArgumentException If one of the provided argument is null or if "calypsoSam" has
     *     a null or unknown product type.
     */
    std::shared_ptr<SamTransactionManagerAdapter> createSamTransactionManagerAdapter(
        std::shared_ptr<CardReader> samReader,
        const std::shared_ptr<CalypsoSam> calypsoSam,
        const std::shared_ptr<SamSecuritySetting> samSecuritySetting,
        const bool isSecureMode) const;
};

}
}
}

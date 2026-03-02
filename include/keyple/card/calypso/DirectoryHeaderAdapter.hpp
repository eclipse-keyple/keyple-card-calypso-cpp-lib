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
#include <string>
#include <vector>

#include "keypop/calypso/card/WriteAccessLevel.hpp"
#include "keypop/calypso/card/card/DirectoryHeader.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keypop::calypso::card::WriteAccessLevel;
using keypop::calypso::card::card::DirectoryHeader;

/**
 * Implementation of DirectoryHeader.
 *
 * @since 2.0.0
 */
class DirectoryHeaderAdapter final : public DirectoryHeader {
public:
    /**
     * CalypsoSamCardSelectorBuilder pattern
     *
     * @since 2.0.0
     */
    class DirectoryHeaderBuilder final {
    public:
        /**
         *
         */
        friend class DirectoryHeaderAdapter;

        /**
         * Sets the LID.
         *
         * @param lid the LID.
         * @return the builder instance
         * @since 2.0.0
         */
        DirectoryHeaderBuilder& lid(std::uint16_t lid);

        /**
         * Sets a reference to the provided access conditions byte array.
         *
         * @param accessConditions the access conditions (should be not null and
         * 4 bytes length).
         * @return the builder instance
         * @since 2.0.0
         */
        DirectoryHeaderBuilder&
        accessConditions(const std::vector<std::uint8_t>& accessConditions);

        /**
         * Sets a reference to the provided key indexes byte array.
         *
         * @param keyIndexes the key indexes (should be not null and 4 bytes
         * length).
         * @return the builder instance
         * @since 2.0.0
         */
        DirectoryHeaderBuilder&
        keyIndexes(const std::vector<std::uint8_t>& keyIndexes);

        /**
         * Sets the DF status.
         *
         * @param dfStatus the DF status (byte).
         * @return the builder instance
         * @since 2.0.0
         */
        DirectoryHeaderBuilder& dfStatus(std::uint8_t dfStatus);

        /**
         * Add a KIF.
         *
         * @param level the KIF session access level (should be not null).
         * @param kif the KIF value.
         * @return the builder instance
         * @since 2.0.0
         */
        DirectoryHeaderBuilder& kif(WriteAccessLevel level, std::uint8_t kif);

        /**
         * Add a KVC.
         *
         * @param level the KVC session access level (should be not null).
         * @param kvc the KVC value.
         * @return the builder instance
         * @since 2.0.0
         */
        DirectoryHeaderBuilder& kvc(WriteAccessLevel level, std::uint8_t kvc);

        /**
         * Build a new DirectoryHeader.
         *
         * @return a new instance
         * @since 2.0.0
         */
        std::unique_ptr<DirectoryHeader> build();

        /**
         *
         */
        friend class DirectoryHeaderAdapter;

    private:
        /**
         *
         */
        std::uint16_t mLid;

        /**
         *
         */
        std::vector<std::uint8_t> mAccessConditions;

        /**
         *
         */
        std::vector<std::uint8_t> mKeyIndexes;

        /**
         *
         */
        std::uint8_t mDfStatus;

        /**
         *
         */
        std::map<const WriteAccessLevel, const std::uint8_t> mKif;

        /**
         *
         */
        std::map<const WriteAccessLevel, const std::uint8_t> mKvc;

        /**
         * Private constructor
         */
        DirectoryHeaderBuilder();
    };

    /**
     * Destructor
     */
    virtual ~DirectoryHeaderAdapter() = default;

    /**
     *
     */
    uint16_t getLid() const override;

    /**
     *
     */
    const std::vector<std::uint8_t>& getAccessConditions() const override;

    /**
     *
     */
    const std::vector<uint8_t>& getKeyIndexes() const override;

    /**
     *
     */
    std::uint8_t getDfStatus() const override;

    /**
     *
     */
    std::uint8_t getKif(WriteAccessLevel writeAccessLevel) const override;

    /**
     *
     */
    std::uint8_t getKvc(WriteAccessLevel writeAccessLevel) const override;

    /**
     * Gets a new builder.
     *
     * @return a new builder instance
     * @since 2.0.0
     */
    static std::unique_ptr<DirectoryHeaderBuilder> builder();

private:
    /**
     *
     */
    const std::uint16_t mLid;

    /**
     *
     */
    const std::vector<std::uint8_t> mAccessConditions;

    /**
     *
     */
    const std::vector<std::uint8_t> mKeyIndexes;

    /**
     *
     */
    const std::uint8_t mDfStatus;

    /**
     *
     */
    const std::map<const WriteAccessLevel, const std::uint8_t> mKif;

    /**
     *
     */
    const std::map<const WriteAccessLevel, const std::uint8_t> mKvc;

    /**
     *
     */
    static const std::string LEVEL_STR;

    /**
     * Private constructor
     */
    DirectoryHeaderAdapter(DirectoryHeaderBuilder* builder);
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */

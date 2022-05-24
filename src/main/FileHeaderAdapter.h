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
#include <ostream>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "FileHeader.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::card;

/**
 * (package-private)<br>
 * Implementation of FileHeader.
 *
 * @since 2.0.0
 */
class FileHeaderAdapter final : public FileHeader {
public:
    /**
     * (package-private)<br>
     * CalypsoSamCardSelectorBuilder pattern
     *
     * @since 2.0.0
     */
    class FileHeaderBuilder {
    public:
        /**
         *
         */
        friend class FileHeaderAdapter;

        /**
         * (package-private)<br>
         * Sets the LID.
         *
         * @param lid the LID.
         * @return The builder instance
         * @since 2.0.0
         */
        FileHeaderBuilder lid(const uint16_t lid);

        /**
         * (package-private)<br>
         * Sets the number of records.
         *
         * @param recordsNumber the number of records (should be {@code >=} 1).
         * @return The builder instance
         * @since 2.0.0
         */
        FileHeaderBuilder recordsNumber(const int recordsNumber);

        /**
         * (package-private)<br>
         * Sets the size of a record.
         *
         * @param recordSize the size of a record (should be {@code >=} 1).
         * @return The builder instance
         * @since 2.0.0
         */
        FileHeaderBuilder recordSize(const int recordSize);

        /**
         * (package-private)<br>
         * Sets the file type.
         *
         * @param type the file type (should be not null).
         * @return The builder instance
         * @since 2.0.0
         */
        FileHeaderBuilder type(const ElementaryFile::Type type);

        /**
         * (package-private)<br>
         * Sets a reference to the provided access conditions byte array.
         *
         * @param accessConditions the access conditions (should be not null and 4 bytes length).
         * @return The builder instance
         * @since 2.0.0
         */
        FileHeaderBuilder accessConditions(const std::vector<uint8_t>& accessConditions);

        /**
         * (package-private)<br>
         * Sets a reference to the provided key indexes byte array.
         *
         * @param keyIndexes the key indexes (should be not null and 4 bytes length).
         * @return The builder instance
         * @since 2.0.0
         */
        FileHeaderBuilder keyIndexes(const std::vector<uint8_t>& keyIndexes);

        /**
         * (package-private)<br>
         * Sets the DF status.
         *
         * @param dfStatus the DF status (byte).
         * @return The builder instance
         * @since 2.0.0
         */
        FileHeaderBuilder dfStatus(const uint8_t dfStatus);

        /**
         * (package-private)<br>
         * Sets the shared reference.
         *
         * @param sharedReference the shared reference.
         * @return The builder instance
         * @since 2.0.0
         */
        FileHeaderBuilder sharedReference(const uint16_t sharedReference);

        /**
         * (package-private)<br>
         * Build a new instance.
         *
         * @return A new instance
         * @since 2.0.0
         */
        std::shared_ptr<FileHeaderAdapter> build();

    private:
        /**
         *
         */
        uint16_t mLid;

        /**
         *
         */
        int mRecordsNumber;

        /**
         *
         */
        int mRecordSize;

        /**
         *
         */
        ElementaryFile::Type mType;

        /**
         *
         */
        std::vector<uint8_t> mAccessConditions;

        /**
         *
         */
        std::vector<uint8_t> mKeyIndexes;

        /**
         *
         */
        std::shared_ptr<uint8_t> mDfStatus;

        /**
         *
         */
        std::shared_ptr<uint16_t> mSharedReference;

        /**
         * Private constructor
         */
        FileHeaderBuilder();
    };

    /**
     *
     */
    friend class FileHeaderBuilder;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint16_t getLid() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    int getRecordsNumber() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    int getRecordSize() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    ElementaryFile::Type getEfType() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getAccessConditions() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getKeyIndexes() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<uint8_t> getDfStatus() const override ;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<uint16_t> getSharedReference() const override;

    /**
     * (package-private)<br>
     * Gets a new builder.
     *
     * @return A new builder instance
     * @since 2.0.0
     */
    static std::shared_ptr<FileHeaderBuilder> builder();

    /**
     * (package-private)<br>
     * Constructor used to create a clone of the provided file header.
     *
     * @param source the header to be cloned.
     * @since 2.0.0
     */
    FileHeaderAdapter(const std::shared_ptr<FileHeader> source);

    /**
     * (package-private)<br>
     * Updates the missing information using the provided source.
     *
     * @param source The header to use.
     * @since 2.1.0
     */
    void updateMissingInfoFrom(const std::shared_ptr<FileHeader> source);

    /**
     * Comparison is based on field "lid".
     *
     * @param o the object to compare.
     * @return The comparison evaluation
     * @since 2.0.0
     */
    bool operator==(const FileHeaderAdapter& o) const;


    /**
     * Comparison is based on field "lid".
     *
     * @param o the object to compare.
     * @return The comparison evaluation
     * @since 2.0.0
     */
    bool operator==(const std::shared_ptr<FileHeaderAdapter> o) const;

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os, const FileHeaderAdapter& fha);

private:
    /**
     *
     */
    const std::uint16_t mLid;

    /**
     *
     */
    const int mRecordsNumber;

    /**
     *
     */
    const int mRecordSize;

    /**
     *
     */
    const ElementaryFile::Type mType;

    /**
     *
     */
    std::vector<uint8_t> mAccessConditions;

    /**
     *
     */
    std::vector<uint8_t> mKeyIndexes;

    /**
     *
     */
    std::shared_ptr<uint8_t> mDfStatus;

    /**
     *
     */
    std::shared_ptr<uint16_t> mSharedReference;

    /**
     * Private constructor
     */
    FileHeaderAdapter(FileHeaderBuilder* builder);
};

}
}
}

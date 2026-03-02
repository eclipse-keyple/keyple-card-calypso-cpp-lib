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

#include "keyple/card/calypso/FileHeaderAdapter.hpp"

#include "keyple/card/calypso/FileHeaderAdapter.hpp"
#include "keyple/core/util/cpp/KeypleStd.hpp"

namespace keyple {
namespace card {
namespace calypso {

FileHeaderAdapter::FileHeaderBuilder::FileHeaderBuilder()
{
}

FileHeaderAdapter::FileHeaderBuilder&
FileHeaderAdapter::FileHeaderBuilder::lid(std::uint16_t lid)
{
    mLid = lid;

    return *this;
}

FileHeaderAdapter::FileHeaderBuilder&
FileHeaderAdapter::FileHeaderBuilder::recordsNumber(int recordsNumber)
{
    mRecordsNumber = recordsNumber;

    return *this;
}

FileHeaderAdapter::FileHeaderBuilder&
FileHeaderAdapter::FileHeaderBuilder::FileHeaderBuilder::recordSize(
    int recordSize)
{
    mRecordSize = recordSize;

    return *this;
}

FileHeaderAdapter::FileHeaderBuilder&
FileHeaderAdapter::FileHeaderBuilder::type(ElementaryFile::Type type)
{
    mType = type;

    return *this;
}

FileHeaderAdapter::FileHeaderBuilder&
FileHeaderAdapter::FileHeaderBuilder::accessConditions(
    const std::vector<uint8_t>& accessConditions)
{
    mAccessConditions = accessConditions;

    return *this;
}

FileHeaderAdapter::FileHeaderBuilder&
FileHeaderAdapter::FileHeaderBuilder::keyIndexes(
    const std::vector<uint8_t>& keyIndexes)
{
    mKeyIndexes = keyIndexes;

    return *this;
}

FileHeaderAdapter::FileHeaderBuilder&
FileHeaderAdapter::FileHeaderBuilder::dfStatus(std::uint8_t dfStatus)
{
    mDfStatus = std::make_shared<uint8_t>(dfStatus);

    return *this;
}

FileHeaderAdapter::FileHeaderBuilder&
FileHeaderAdapter::FileHeaderBuilder::sharedReference(
    std::uint16_t sharedReference)
{
    mSharedReference = std::make_shared<uint16_t>(sharedReference);

    return *this;
}

std::shared_ptr<FileHeaderAdapter>
FileHeaderAdapter::FileHeaderBuilder::build()
{
    return std::shared_ptr<FileHeaderAdapter>(new FileHeaderAdapter(this));
}

std::uint16_t
FileHeaderAdapter::getLid() const
{
    return mLid;
}

int
FileHeaderAdapter::getRecordsNumber() const
{
    return mRecordsNumber;
}

int
FileHeaderAdapter::getRecordSize() const
{
    return mRecordSize;
}

ElementaryFile::Type
FileHeaderAdapter::getEfType() const
{
    return mType;
}

const std::vector<std::uint8_t>&
FileHeaderAdapter::getAccessConditions() const
{
    return mAccessConditions;
}

const std::vector<std::uint8_t>&
FileHeaderAdapter::getKeyIndexes() const
{
    return mKeyIndexes;
}

const std::shared_ptr<std::uint8_t>&
FileHeaderAdapter::getDfStatus() const
{
    return mDfStatus;
}

const std::shared_ptr<std::uint16_t>
FileHeaderAdapter::getSharedReference() const
{
    return mSharedReference;
}

std::shared_ptr<FileHeaderAdapter::FileHeaderBuilder>
FileHeaderAdapter::builder()
{
    return std::shared_ptr<FileHeaderBuilder>(new FileHeaderBuilder());
}

FileHeaderAdapter::FileHeaderAdapter(const std::shared_ptr<FileHeader>& source)
: mLid(source->getLid())
, mRecordsNumber(source->getRecordsNumber())
, mRecordSize(source->getRecordSize())
, mType(source->getEfType())
, mAccessConditions(source->getAccessConditions())
, mKeyIndexes(source->getKeyIndexes())
, mDfStatus(source->getDfStatus())
, mSharedReference(source->getSharedReference())
{
}

void
FileHeaderAdapter::updateMissingInfoFrom(const FileHeader& source)
{
    if (mAccessConditions.empty()) {
        mAccessConditions = source.getAccessConditions();
    }

    if (mKeyIndexes.empty()) {
        mKeyIndexes = source.getKeyIndexes();
    }

    if (mDfStatus == nullptr) {
        mDfStatus = source.getDfStatus();
    }

    if (mSharedReference == nullptr) {
        mSharedReference = source.getSharedReference();
    }
}

bool
FileHeaderAdapter::operator==(const FileHeaderAdapter& o) const
{
    return mLid == o.mLid;
}

bool
FileHeaderAdapter::operator==(const std::shared_ptr<FileHeaderAdapter> o) const
{
    if (o == nullptr) {
        return false;
    }

    if (this == o.get()) {
        return true;
    }

    return *this == *o.get();
}

std::ostream&
operator<<(std::ostream& os, const FileHeaderAdapter& fha)
{
    os << "FILE_HEADER_ADAPTER: {"
       << "LID = " << fha.mLid << ", "
       << "RECORDS_NUMBER = " << fha.mRecordsNumber << ", "
       << "RECORD_SIZE = " << fha.mRecordSize << ", "
       << "TYPE = " << fha.mType << ", "
       << "ACCESS_CONDITIONS = " << fha.mAccessConditions << ", "
       << "KEY_INDEXES = " << fha.mKeyIndexes << ", "
       << "DF_STATUS = " << fha.mDfStatus << ", "
       << "SHARED_REFERENCE = " << fha.mSharedReference << "}";

    return os;
}

std::ostream&
operator<<(std::ostream& os, const std::shared_ptr<FileHeaderAdapter> fha)
{
    if (fha == nullptr) {
        os << "FILE_HEADER_ADAPTER: {null}";
    } else {
        os << *fha.get();
    }

    return os;
}

FileHeaderAdapter::FileHeaderAdapter(FileHeaderBuilder* builder)
: mLid(builder->mLid)
, mRecordsNumber(builder->mRecordsNumber)
, mRecordSize(builder->mRecordSize)
, mType(builder->mType)
, mAccessConditions(builder->mAccessConditions)
, mKeyIndexes(builder->mKeyIndexes)
, mDfStatus(builder->mDfStatus)
, mSharedReference(builder->mSharedReference)
{
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */

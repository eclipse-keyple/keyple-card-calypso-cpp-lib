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

#include "FileHeaderAdapter.h"

/* Keyple Core Util */
#include "KeypleStd.h"

namespace keyple {
namespace card {
namespace calypso {

using FileHeaderBuilder = FileHeaderAdapter::FileHeaderBuilder;

/* FILE HEADER BUILDER -------------------------------------------------------------------------- */

FileHeaderBuilder::FileHeaderBuilder() {}

FileHeaderBuilder FileHeaderBuilder::lid(const uint16_t lid)
{
    mLid = lid;

    return *this;
}

FileHeaderBuilder FileHeaderBuilder::recordsNumber(const int recordsNumber)
{
    mRecordsNumber = recordsNumber;

    return *this;
}

FileHeaderBuilder FileHeaderBuilder::recordSize(const int recordSize)
{
    mRecordSize = recordSize;

    return *this;
}

FileHeaderBuilder FileHeaderBuilder::type(const ElementaryFile::Type type)
{
    mType = type;

    return *this;
}

FileHeaderBuilder FileHeaderBuilder::accessConditions(const std::vector<uint8_t>& accessConditions)
{
    mAccessConditions = accessConditions;

    return *this;
}

FileHeaderBuilder FileHeaderBuilder::keyIndexes(const std::vector<uint8_t>& keyIndexes)
{
    mKeyIndexes = keyIndexes;

    return *this;
}

FileHeaderBuilder FileHeaderBuilder::dfStatus(const uint8_t dfStatus)
{
    mDfStatus = std::make_shared<uint8_t>(dfStatus);

    return *this;
}

FileHeaderBuilder FileHeaderBuilder::sharedReference(const uint16_t sharedReference)
{
    mSharedReference = std::make_shared<uint16_t>(sharedReference);

    return *this;
}

std::shared_ptr<FileHeaderAdapter> FileHeaderBuilder::build()
{
    return std::shared_ptr<FileHeaderAdapter>(new FileHeaderAdapter(this));
}

/* FILE HEADER ADAPTER -------------------------------------------------------------------------- */

uint16_t FileHeaderAdapter::getLid() const
{
    return mLid;
}

int FileHeaderAdapter::getRecordsNumber() const
{
    return mRecordsNumber;
}

/**
 * {@inheritDoc}
 *
 * @since 2.0.0
 */
int FileHeaderAdapter::getRecordSize() const
{
    return mRecordSize;
}

ElementaryFile::Type FileHeaderAdapter::getEfType() const
{
    return mType;
}

const std::vector<uint8_t>& FileHeaderAdapter::getAccessConditions() const
{
    return mAccessConditions;
}

const std::vector<uint8_t>& FileHeaderAdapter::getKeyIndexes() const
{
    return mKeyIndexes;
}

const std::shared_ptr<uint8_t> FileHeaderAdapter::getDfStatus() const
{
    return mDfStatus;
}

const std::shared_ptr<uint16_t> FileHeaderAdapter::getSharedReference() const
{
    return mSharedReference;
}

std::shared_ptr<FileHeaderBuilder> FileHeaderAdapter::builder()
{
    return std::shared_ptr<FileHeaderBuilder>(new FileHeaderBuilder());
}

FileHeaderAdapter::FileHeaderAdapter(const std::shared_ptr<FileHeader> source)
: mLid(source->getLid()),
  mRecordsNumber(source->getRecordsNumber()),
  mRecordSize(source->getRecordSize()),
  mType(source->getEfType()),
  mAccessConditions(source->getAccessConditions()),
  mKeyIndexes(source->getKeyIndexes()),
  mDfStatus(source->getDfStatus()),
  mSharedReference(source->getSharedReference()) {}

void FileHeaderAdapter::updateMissingInfoFrom(const std::shared_ptr<FileHeader> source)
{
    if (mAccessConditions.empty()) {
        mAccessConditions = source->getAccessConditions();
    }

    if (mKeyIndexes.empty()) {
        mKeyIndexes = source->getKeyIndexes();
    }

    if (mDfStatus == nullptr) {
        mDfStatus = source->getDfStatus();
    }

    if (mSharedReference == nullptr) {
        mSharedReference = source->getSharedReference();
    }
}

bool FileHeaderAdapter::operator==(const FileHeaderAdapter& o) const
{
    return mLid == o.mLid;
}

bool FileHeaderAdapter::operator==(const std::shared_ptr<FileHeaderAdapter> o) const
{
    if (o == nullptr) {
        return false;
    }

    if (this == o.get()) {
        return true;
    }

    return *this == *o.get();
}

std::ostream& operator<<(std::ostream& os, const FileHeaderAdapter& fha)
{
    os << "FILE_HEADER_ADAPTER: {"
       << "LID = " << fha.mLid << ", "
       << "RECORDS_NUMBER = " << fha.mRecordsNumber << ", "
       << "RECORD_SIZE = " << fha.mRecordSize << ", "
       << "TYPE = " << fha.mType << ", "
       << "ACCESS_CONDITIONS = " << fha.mAccessConditions << ", "
       << "KEY_INDEXES = " << fha.mKeyIndexes << ", "
       << "DF_STATUS = " << fha.mDfStatus << ", "
       << "SHARED_REFERENCE = " << fha.mSharedReference
       << "}";

    return os;
}

std::ostream& operator<<(std::ostream& os, const std::shared_ptr<FileHeaderAdapter> fha)
{
    if (fha == nullptr) {
        os << "FILE_HEADER_ADAPTER: {null}";
    } else {
        os << *fha.get();
    }

    return os;
}

FileHeaderAdapter::FileHeaderAdapter(FileHeaderBuilder* builder)
: mLid(builder->mLid),
  mRecordsNumber(builder->mRecordsNumber),
  mRecordSize(builder->mRecordSize),
  mType(builder->mType),
  mAccessConditions(builder->mAccessConditions),
  mKeyIndexes(builder->mKeyIndexes),
  mDfStatus(builder->mDfStatus),
  mSharedReference(builder->mSharedReference) {}

}
}
}

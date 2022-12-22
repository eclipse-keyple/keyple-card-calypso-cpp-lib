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

#include "FileDataAdapter.h"

/* Keyple Core Util */
#include "Arrays.h"
#include "ByteArrayUtil.h"
#include "IndexOutOfBoundsException.h"
#include "KeypleAssert.h"
#include "KeypleStd.h"
#include "System.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

FileDataAdapter::FileDataAdapter() {}

FileDataAdapter::FileDataAdapter(const std::shared_ptr<FileData> source)
{
    const std::map<const uint8_t, std::vector<uint8_t>>& sourceContent =
        source->getAllRecordsContent();

    for (const auto& entry : sourceContent) {
        mRecords.insert({entry.first, entry.second});
    }
}

const std::map<const uint8_t, std::vector<uint8_t>>& FileDataAdapter::getAllRecordsContent()
    const
{
    return mRecords;
}

const std::vector<uint8_t> FileDataAdapter::getContent() const
{
    return getContent(1);
}

const std::vector<uint8_t> FileDataAdapter::getContent(const uint8_t numRecord) const
{
    const auto it = mRecords.find(numRecord);
    if (it == mRecords.end()) {
        mLogger->warn("Record #% is not set\n", numRecord);
        return std::vector<uint8_t>();
    } else {
        return it->second;
    }
}

const std::vector<uint8_t> FileDataAdapter::getContent(const uint8_t numRecord,
                                                       const uint8_t dataOffset,
                                                       const uint8_t dataLength) const
{
    Assert::getInstance().greaterOrEqual(dataOffset, 0, "dataOffset")
                         .greaterOrEqual(dataLength, 1, "dataLength");

    const auto it = mRecords.find(numRecord);
    if (it == mRecords.end()) {
        mLogger->warn("Record #% is not set\n", numRecord);
        return std::vector<uint8_t>();
    }

    const std::vector<uint8_t>& content = it->second;
    if (dataOffset >= static_cast<int>(content.size())) {
        throw IndexOutOfBoundsException("Offset [" + std::to_string(dataOffset) + "] >= " +
                                        "content length [" + std::to_string(content.size()) + "].");
    }

    const int toIndex = dataOffset + dataLength;
    if (toIndex > static_cast<int>(content.size())) {
        throw IndexOutOfBoundsException("Offset [" + std::to_string(dataOffset) + "] + " +
                                        "Length [" + std::to_string(dataLength) + "] = " +
                                        "[" + std::to_string(toIndex) + "] > " +
                                        "content length [" + std::to_string(content.size()) + "].");
    }

    return Arrays::copyOfRange(content, dataOffset, toIndex);
}

const std::shared_ptr<int> FileDataAdapter::getContentAsCounterValue(const int numCounter) const
{
    Assert::getInstance().greaterOrEqual(numCounter, 1, "numCounter");

    const auto it = mRecords.find(1);
    if (it == mRecords.end()) {
        mLogger->warn("Record #1 is not set\n");
        return nullptr;
    }

    const std::vector<uint8_t>& rec1 = it->second;
    const int counterIndex = (numCounter - 1) * 3;
    if (counterIndex >= static_cast<int>(rec1.size())) {
        mLogger->warn("Counter #% is not set (nb of actual counters = %)\n",
                        numCounter,
                        rec1.size() / 3);
        return nullptr;
    }

    if (counterIndex + 3 > static_cast<int>(rec1.size())) {
        throw IndexOutOfBoundsException("Counter #" + std::to_string(numCounter) + " " +
                                        "has a truncated value (nb of actual counters = " +
                                        std::to_string(rec1.size() / 3) + ").");
    }

    return std::make_shared<int>(ByteArrayUtil::extractInt(rec1, counterIndex, 3, false));
}

const std::map<const int, const int> FileDataAdapter::getAllCountersValue() const
{
    std::map<const int, const int> result;

    const auto it = mRecords.find(1);

    if (it == mRecords.end()) {
        mLogger->warn("Record #1 is not set\n");
        return result;
    }

    const std::vector<uint8_t> rec1 = it->second;
    const int length = static_cast<int>(rec1.size() - (rec1.size() % 3));
    for (int i = 0, c = 1; i < length; i += 3, c++) {
        result.insert({c, ByteArrayUtil::extractInt(rec1, i, 3, false)});
    }

    return result;
}

void FileDataAdapter::setContent(const uint8_t numRecord, const std::vector<uint8_t>& content)
{
    mRecords[numRecord] = content;
}

void FileDataAdapter::setCounter(const uint8_t numCounter, const std::vector<uint8_t>& content)
{
    setContent(1, content, (numCounter - 1) * 3);
}

void FileDataAdapter::setContent(const uint8_t numRecord,
                                 const std::vector<uint8_t> content,
                                 const uint8_t offset)
{
    std::vector<uint8_t> newContent;
    const int newLength = static_cast<int>(offset + content.size());

    const auto it = mRecords.find(numRecord);
    if (it == mRecords.end()) {
        newContent = std::vector<uint8_t>(newLength);
    } else {
        const std::vector<uint8_t> oldContent = it->second;
        if (static_cast<int>(oldContent.size()) <= offset) {
            newContent = std::vector<uint8_t>(newLength);
            System::arraycopy(oldContent, 0, newContent, 0, oldContent.size());
        } else if (static_cast<int>(oldContent.size()) < newLength) {
            newContent = std::vector<uint8_t>(newLength);
            System::arraycopy(oldContent, 0, newContent, 0, offset);
        } else {
            newContent = oldContent;
        }
    }

    System::arraycopy(content, 0, newContent, offset, content.size());

    mRecords[numRecord] = newContent;
}

void FileDataAdapter::fillContent(const uint8_t numRecord,
                                  const std::vector<uint8_t> content,
                                  const uint8_t offset)
{
    std::vector<uint8_t> contentLeftPadded = content;

    if (offset != 0) {
        contentLeftPadded = std::vector<uint8_t>(offset + content.size());
        System::arraycopy(content, 0, contentLeftPadded, offset, content.size());
    }

    const auto it = mRecords.find(numRecord);
    if (it == mRecords.end()) {
        mRecords[numRecord] = contentLeftPadded;
    } else {
        /* Make sure it's a non-const reference as it is updated in-place in the 'else' section */
        std::vector<uint8_t>& actualContent = it->second;

        if (actualContent.size() < contentLeftPadded.size()) {
            for (int i = 0; i < static_cast<int>(actualContent.size()); i++) {
                contentLeftPadded[i] |= actualContent[i];
            }

            mRecords[numRecord] = contentLeftPadded;
        } else {
            for (int i = 0; i < static_cast<int>(contentLeftPadded.size()); i++) {
                actualContent[i] |= contentLeftPadded[i];
            }
        }
    }
}

void FileDataAdapter::addCyclicContent(const std::vector<uint8_t>& content)
{
    std::vector<uint8_t> descendingKeys;

    for (auto it = mRecords.rbegin(); it != mRecords.rend(); ++it) {
        descendingKeys.push_back(it->first);
    }

    for (const auto& i : descendingKeys) {
        mRecords[static_cast<uint8_t>(i + 1)] = mRecords[i];
    }

    mRecords[static_cast<uint8_t>(1)] = content;
}

std::ostream& operator<<(std::ostream& os, const FileDataAdapter& fda)
{
    os << "FILE_DATA_ADAPTER: {"
       << "RECORDS = " << fda.mRecords
       << "}";

    return os;
}

}
}
}

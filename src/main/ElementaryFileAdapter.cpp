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

#include "ElementaryFileAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

ElementaryFileAdapter::ElementaryFileAdapter(const uint8_t sfi)
: mSfi(sfi), mData(std::make_shared<FileDataAdapter>()) {}

ElementaryFileAdapter::ElementaryFileAdapter(const std::shared_ptr<ElementaryFile> source)
: mSfi(source->getSfi()),
  mHeader(source->getHeader() != nullptr ?
          std::make_shared<FileHeaderAdapter>(source->getHeader()) : nullptr),
  mData(std::make_shared<FileDataAdapter>(source->getData())) {}

ElementaryFile& ElementaryFileAdapter::setHeader(const std::shared_ptr<FileHeaderAdapter> header)
{
    mHeader = header;

    return *this;
}

uint8_t ElementaryFileAdapter::getSfi() const
{
    return mSfi;
}

const std::shared_ptr<FileHeader> ElementaryFileAdapter::getHeader() const
{
    return mHeader;
}

const std::shared_ptr<FileData> ElementaryFileAdapter::getData() const
{
    return mData;
}

bool ElementaryFileAdapter::operator==(const ElementaryFileAdapter& o) const
{
    return mSfi == o.mSfi;
}

bool ElementaryFileAdapter::operator==(const std::shared_ptr<ElementaryFileAdapter> o) const
{
    if (o == nullptr) {
        return false;
    }

    if (this == o.get()) {
        return true;
    }

    return *this == *o.get();
}

std::ostream& operator<<(std::ostream& os, const ElementaryFileAdapter& fha)
{
    os << "ELEMENTARY_FILE_ADAPTER: {"
       << "SFI = " << fha.mSfi << ", "
       << "HEADER = " << fha.mHeader << ", "
       << "DATA = " << fha.mData
       << "}";

    return os;
}

std::ostream& operator<<(std::ostream& os, const std::shared_ptr<ElementaryFileAdapter> fha)
{
    if (fha == nullptr) {
        os << "ELEMENTARY_FILE_ADAPTER: {null}";
    } else {
        os << *fha.get();
    }

    return os;
}

}
}
}

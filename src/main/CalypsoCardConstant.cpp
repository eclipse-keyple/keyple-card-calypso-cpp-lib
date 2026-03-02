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

#include "keyple/card/calypso/CalypsoCardConstant.hpp"

#include <vector>

#include "keyple/core/util/HexUtil.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::HexUtil;

const int CalypsoCardConstant::SW_FILE_NOT_FOUND = 0x6A82;
const int CalypsoCardConstant::SW_RECORD_NOT_FOUND = 0x6A83;

const int CalypsoCardConstant::MASK_15_BITS = 0x7FFF;   /* 32 767 */
const int CalypsoCardConstant::MASK_3_BYTES = 0xFFFFFF; /* 16 777 215 */

/* SFI */
const int CalypsoCardConstant::SFI_MIN = 0;
const int CalypsoCardConstant::SFI_MAX = 30; /* 1Eh */

/* Record number */
const int CalypsoCardConstant::NB_REC_MIN = 1;
const int CalypsoCardConstant::NB_REC_MAX = 250;

/* Counter number */
const int CalypsoCardConstant::NUM_CNT_MIN = 1;

/* Counter value */
const int CalypsoCardConstant::CNT_VALUE_MIN = 0;
const int CalypsoCardConstant::CNT_VALUE_MAX = MASK_3_BYTES;

/* Offset */
const int CalypsoCardConstant::OFFSET_MIN = 0;
const int CalypsoCardConstant::OFFSET_MAX = 249;
const int CalypsoCardConstant::OFFSET_BINARY_MAX = MASK_15_BITS;

/* Data */
const int CalypsoCardConstant::DATA_LENGTH_MIN = 1;

/* Field offsets in select file response (tag/length excluded) */
const int CalypsoCardConstant::SEL_SFI_OFFSET = 0;
const int CalypsoCardConstant::SEL_TYPE_OFFSET = 1;
const int CalypsoCardConstant::SEL_EF_TYPE_OFFSET = 2;
const int CalypsoCardConstant::SEL_REC_SIZE_OFFSET = 3;
const int CalypsoCardConstant::SEL_NUM_REC_OFFSET = 4;
const int CalypsoCardConstant::SEL_AC_OFFSET = 5;
const int CalypsoCardConstant::SEL_AC_LENGTH = 4;
const int CalypsoCardConstant::SEL_NKEY_OFFSET = 9;
const int CalypsoCardConstant::SEL_NKEY_LENGTH = 4;
const int CalypsoCardConstant::SEL_DF_STATUS_OFFSET = 13;
const int CalypsoCardConstant::SEL_KVCS_OFFSET = 14;
const int CalypsoCardConstant::SEL_KIFS_OFFSET = 17;
const int CalypsoCardConstant::SEL_DATA_REF_OFFSET = 14;
const int CalypsoCardConstant::SEL_LID_OFFSET = 21;
const int CalypsoCardConstant::SEL_LID_OFFSET_REV2 = 20;

/* PIN Code */
const int CalypsoCardConstant::PIN_LENGTH = 4;

/* Stored Value */
const uint8_t CalypsoCardConstant::STORED_VALUE_FILE_STRUCTURE_ID = 0x20;
const uint8_t CalypsoCardConstant::SV_RELOAD_LOG_FILE_SFI = 0x14;
const uint8_t CalypsoCardConstant::SV_RELOAD_LOG_FILE_NB_REC = 1;
const uint8_t CalypsoCardConstant::SV_DEBIT_LOG_FILE_SFI = 0x15;
const uint8_t CalypsoCardConstant::SV_DEBIT_LOG_FILE_NB_REC = 3;
const uint8_t CalypsoCardConstant::SV_LOG_FILE_REC_LENGTH = 29;

/* Payload capacity */
const int CalypsoCardConstant::SV_LOAD_MIN_VALUE
    = -8388608;  // -2^23: smallest 3-byte negative value
const int CalypsoCardConstant::SV_LOAD_MAX_VALUE
    = 8388607;  //  2^23 - 1: largest 3-byte positive value
const int CalypsoCardConstant::SV_DEBIT_MIN_VALUE = 0;
const int CalypsoCardConstant::SV_DEBIT_MAX_VALUE
    = 32767;  // 2^15 - 1: largest 2-byte positive value

const int CalypsoCardConstant::DEFAULT_PAYLOAD_CAPACITY = 250;

const int CalypsoCardConstant::LEGACY_REC_LENGTH = 29;

const int CalypsoCardConstant::CARD_PUBLIC_KEY_SIZE = 64;
const int CalypsoCardConstant::CARD_KEY_PAIR_SIZE = 96;
const int CalypsoCardConstant::CARD_CERTIFICATE_SIZE = 316;
const int CalypsoCardConstant::CA_CERTIFICATE_SIZE = 384;

/* TLV TAGS */
const int CalypsoCardConstant::TAG_FCP_FOR_CURRENT_FILE = 0x62;
const std::uint8_t CalypsoCardConstant::TAG_FCP_FOR_CURRENT_FILE_LSB
    = (TAG_FCP_FOR_CURRENT_FILE & 0xFF);
const std::uint8_t CalypsoCardConstant::TAG_FCP_FOR_CURRENT_FILE_MSB
    = ((TAG_FCP_FOR_CURRENT_FILE & 0xFF00) >> 8);
const int CalypsoCardConstant::TAG_FCI_FOR_CURRENT_DF = 0x6F;
const std::uint8_t CalypsoCardConstant::TAG_FCI_FOR_CURRENT_DF_LSB
    = (TAG_FCI_FOR_CURRENT_DF & 0xFF);
const std::uint8_t CalypsoCardConstant::TAG_FCI_FOR_CURRENT_DF_MSB
    = ((TAG_FCI_FOR_CURRENT_DF & 0xFF00) >> 8);
const int CalypsoCardConstant::TAG_EF_LIST = 0xC0;
const std::uint8_t CalypsoCardConstant::TAG_EF_LIST_LSB = (TAG_EF_LIST & 0xFF);
const std::uint8_t CalypsoCardConstant::TAG_EF_LIST_MSB
    = ((TAG_EF_LIST & 0xFF00) >> 8);
const int CalypsoCardConstant::TAG_TRACEABILITY_INFORMATION = 0x185;
const std::uint8_t CalypsoCardConstant::TAG_TRACEABILITY_INFORMATION_LSB
    = (TAG_TRACEABILITY_INFORMATION & 0xFF);
const std::uint8_t CalypsoCardConstant::TAG_TRACEABILITY_INFORMATION_MSB
    = ((TAG_TRACEABILITY_INFORMATION & 0xFF00) >> 8);
const int CalypsoCardConstant::TAG_CARD_PUBLIC_KEY_HEADER_SIZE = 3;
const int CalypsoCardConstant::TAG_CARD_PUBLIC_KEY = 0xDF2C;
const std::uint8_t CalypsoCardConstant::TAG_CARD_PUBLIC_KEY_LSB
    = (TAG_CARD_PUBLIC_KEY & 0xFF);
const std::uint8_t CalypsoCardConstant::TAG_CARD_PUBLIC_KEY_MSB
    = ((TAG_CARD_PUBLIC_KEY & 0xFF00) >> 8);
const int CalypsoCardConstant::TAG_CARD_KEY_PAIR = 0xDF3C;
const std::uint8_t CalypsoCardConstant::TAG_CARD_KEY_PAIR_LSB
    = (TAG_CARD_KEY_PAIR & 0xFF);
const std::uint8_t CalypsoCardConstant::TAG_CARD_KEY_PAIR_MSB
    = ((TAG_CARD_KEY_PAIR & 0xFF00) >> 8);
const int CalypsoCardConstant::TAG_CERTIFICATE_HEADER_SIZE = 5;
const int CalypsoCardConstant::TAG_CARD_CERTIFICATE = 0xDF4C;
const std::vector<std::uint8_t> CalypsoCardConstant::TAG_CARD_CERTIFICATE_HEADER
    = HexUtil::toByteArray("DF4C82013C");
const std::uint8_t CalypsoCardConstant::TAG_CARD_CERTIFICATE_LSB
    = (TAG_CARD_CERTIFICATE & 0xFF);
const std::uint8_t CalypsoCardConstant::TAG_CARD_CERTIFICATE_MSB
    = ((TAG_CARD_CERTIFICATE & 0xFF00) >> 8);
const int CalypsoCardConstant::TAG_CA_CERTIFICATE = 0xDF4A;
const std::vector<std::uint8_t> CalypsoCardConstant::TAG_CA_CERTIFICATE_HEADER
    = HexUtil::toByteArray("DF4A820180");
const std::uint8_t CalypsoCardConstant::TAG_CA_CERTIFICATE_LSB
    = (TAG_CA_CERTIFICATE & 0xFF);
const std::uint8_t CalypsoCardConstant::TAG_CA_CERTIFICATE_MSB
    = ((TAG_CA_CERTIFICATE & 0xFF00) >> 8);

CalypsoCardConstant::CalypsoCardConstant()
{
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */

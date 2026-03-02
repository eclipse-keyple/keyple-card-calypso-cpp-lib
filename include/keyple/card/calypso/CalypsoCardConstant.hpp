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
#include <vector>

namespace keyple {
namespace card {
namespace calypso {

/**
 * Constants related to Calypso cards.
 *
 * @since 2.0.0
 */
class CalypsoCardConstant final {
public:
    /* SW */
    static const int SW_FILE_NOT_FOUND;
    static const int SW_RECORD_NOT_FOUND;

    static const int MASK_15_BITS;
    static const int MASK_3_BYTES;

    /* SFI */
    static const int SFI_MIN;
    static const int SFI_MAX;

    /* Record number */
    static const int NB_REC_MIN;
    static const int NB_REC_MAX;

    /* Counter number */
    static const int NUM_CNT_MIN;

    /* Counter value */
    static const int CNT_VALUE_MIN;
    static const int CNT_VALUE_MAX;

    /* Offset */
    static const int OFFSET_MIN;
    static const int OFFSET_MAX;
    static const int OFFSET_BINARY_MAX;

    /* Data */
    static const int DATA_LENGTH_MIN;

    /* File Type Values */
    static constexpr int FILE_TYPE_MF = 1;
    static constexpr int FILE_TYPE_DF = 2;
    static constexpr int FILE_TYPE_EF = 4;

    /* EF Type Values */
    static constexpr int EF_TYPE_DF = 0;
    static constexpr int EF_TYPE_BINARY = 1;
    static constexpr int EF_TYPE_LINEAR = 2;
    static constexpr int EF_TYPE_CYCLIC = 4;
    static constexpr int EF_TYPE_SIMULATED_COUNTERS = 8;
    static constexpr int EF_TYPE_COUNTERS = 9;

    /* Field offsets in select file response (tag/length excluded) */
    static const int SEL_SFI_OFFSET;
    static const int SEL_TYPE_OFFSET;
    static const int SEL_EF_TYPE_OFFSET;
    static const int SEL_REC_SIZE_OFFSET;
    static const int SEL_NUM_REC_OFFSET;
    static const int SEL_AC_OFFSET;
    static const int SEL_AC_LENGTH;
    static const int SEL_NKEY_OFFSET;
    static const int SEL_NKEY_LENGTH;
    static const int SEL_DF_STATUS_OFFSET;
    static const int SEL_KVCS_OFFSET;
    static const int SEL_KIFS_OFFSET;
    static const int SEL_DATA_REF_OFFSET;
    static const int SEL_LID_OFFSET;
    static const int SEL_LID_OFFSET_REV2;

    /* PIN Code */
    static const int PIN_LENGTH;

    /* Stored Value */
    static const uint8_t STORED_VALUE_FILE_STRUCTURE_ID;
    static const uint8_t SV_RELOAD_LOG_FILE_SFI;
    static const uint8_t SV_RELOAD_LOG_FILE_NB_REC;
    static const uint8_t SV_DEBIT_LOG_FILE_SFI;
    static const uint8_t SV_DEBIT_LOG_FILE_NB_REC;
    static const uint8_t SV_LOG_FILE_REC_LENGTH;

    /* Payload capacity */
    static const int SV_LOAD_MIN_VALUE;
    static const int SV_LOAD_MAX_VALUE;
    static const int SV_DEBIT_MIN_VALUE;
    static const int SV_DEBIT_MAX_VALUE;

    static const int DEFAULT_PAYLOAD_CAPACITY;

    static const int LEGACY_REC_LENGTH;

    static const int CARD_PUBLIC_KEY_SIZE;
    static const int CARD_KEY_PAIR_SIZE;
    static const int CARD_CERTIFICATE_SIZE;
    static const int CA_CERTIFICATE_SIZE;

    /* TLV TAGS */
    static const int TAG_FCP_FOR_CURRENT_FILE;
    static const std::uint8_t TAG_FCP_FOR_CURRENT_FILE_LSB;
    static const std::uint8_t TAG_FCP_FOR_CURRENT_FILE_MSB;
    static const int TAG_FCI_FOR_CURRENT_DF;
    static const std::uint8_t TAG_FCI_FOR_CURRENT_DF_LSB;
    static const std::uint8_t TAG_FCI_FOR_CURRENT_DF_MSB;
    static const int TAG_EF_LIST;
    static const std::uint8_t TAG_EF_LIST_LSB;
    static const std::uint8_t TAG_EF_LIST_MSB;
    static const int TAG_TRACEABILITY_INFORMATION;
    static const std::uint8_t TAG_TRACEABILITY_INFORMATION_LSB;
    static const std::uint8_t TAG_TRACEABILITY_INFORMATION_MSB;
    static const int TAG_CARD_PUBLIC_KEY_HEADER_SIZE;
    static const int TAG_CARD_PUBLIC_KEY;
    static const std::uint8_t TAG_CARD_PUBLIC_KEY_LSB;
    static const std::uint8_t TAG_CARD_PUBLIC_KEY_MSB;
    static const int TAG_CARD_KEY_PAIR;
    static const std::uint8_t TAG_CARD_KEY_PAIR_LSB;
    static const std::uint8_t TAG_CARD_KEY_PAIR_MSB;
    static const int TAG_CERTIFICATE_HEADER_SIZE;
    static const int TAG_CARD_CERTIFICATE;
    static const std::vector<std::uint8_t> TAG_CARD_CERTIFICATE_HEADER;
    static const std::uint8_t TAG_CARD_CERTIFICATE_LSB;
    static const std::uint8_t TAG_CARD_CERTIFICATE_MSB;
    static const int TAG_CA_CERTIFICATE;
    static const std::vector<std::uint8_t> TAG_CA_CERTIFICATE_HEADER;
    static const std::uint8_t TAG_CA_CERTIFICATE_LSB;
    static const std::uint8_t TAG_CA_CERTIFICATE_MSB;

private:
    /**
     * (private)
     */
    CalypsoCardConstant();
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */

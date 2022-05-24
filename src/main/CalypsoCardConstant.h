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

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Constants related to Calypso cards.
 *
 * @since 2.0.0
 */
class CalypsoCardConstant final {
public:
    static const int MASK_15_BITS;
    static const int MASK_3_BYTES;

    /* SFI */
    static const int SFI_MIN;
    static const int SFI_MAX;

    /* Record number */
    static const int NB_REC_MIN;
    static const int NB_REC_MAX;

    /* Counter number */
    static const int NB_CNT_MIN;
    static const int NB_CNT_MAX;

    /* Counter value */
    static const int CNT_VALUE_MIN;
    static const int CNT_VALUE_MAX;

    /* Offset */
    static const int OFFSET_MIN;
    static const int OFFSET_MAX;
    static const int OFFSET_BINARY_MAX;

    /* Data */
    static const int DATA_LENGTH_MIN;
    static const int DATA_LENGTH_MAX;

    /* File Type Values */
    static const int FILE_TYPE_MF;
    static const int FILE_TYPE_DF;
    static const int FILE_TYPE_EF;

    /* EF Type Values */
    static const int EF_TYPE_DF;
    static const int EF_TYPE_BINARY;
    static const int EF_TYPE_LINEAR;
    static const int EF_TYPE_CYCLIC;
    static const int EF_TYPE_SIMULATED_COUNTERS;
    static const int EF_TYPE_COUNTERS;

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

    /* PIN Code */
    static const int PIN_LENGTH;

    /* Stored Value */
    static const uint8_t STORED_VALUE_FILE_STRUCTURE_ID;
    static const uint8_t SV_RELOAD_LOG_FILE_SFI;
    static const int SV_RELOAD_LOG_FILE_NB_REC;
    static const uint8_t SV_DEBIT_LOG_FILE_SFI;
    static const int SV_DEBIT_LOG_FILE_NB_REC;
    static const int SV_LOG_FILE_REC_LENGTH;

    /* Payload capacity */
    static const int PAYLOAD_CAPACITY_PRIME_REV3;

private:
    /**
     * (private)
     */
    CalypsoCardConstant();
};

}
}
}

// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;

// unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/** calculate targets for xds */
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const bool is_target_requested_for_pos, const Consensus::Params&);

unsigned int GetNextRatchetTargetRequired(const CBlockIndex* pindexLast, const bool is_pindexLast_pos, const bool is_target_requested_for_pos, const Consensus::Params&);
unsigned int GetNextPosTargetRequired(const CBlockIndex* pindexLastPos, const Consensus::Params& params);
unsigned int GetNextPowTargetRequired(const CBlockIndex* pindexLastPow, const Consensus::Params& params);
unsigned int CalculatePosRetarget(uint32_t lastPosBlockTime, uint32_t lastPosBlockBits, uint32_t previousPosBlockTime, const Consensus::Params&, uint64_t height);
/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);

#endif // BITCOIN_POW_H

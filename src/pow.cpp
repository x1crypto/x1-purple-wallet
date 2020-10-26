// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight + 1) % params.DifficultyAdjustmentInterval() != 0) {
        if (params.fPowAllowMinDifficultyBlocks) {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)
                return nProofOfWorkLimit;
            else {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval() - 1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowPosNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan / 4)
        nActualTimespan = params.nPowTargetTimespan / 4;
    if (nActualTimespan > params.nPowTargetTimespan * 4)
        nActualTimespan = params.nPowTargetTimespan * 4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const bool is_proof_of_stake, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    if (params.fPowPosNoRetargeting)
        return pindexLast->nBits;

    const arith_uint256 nTargetLimit = is_proof_of_stake ? UintToArith256(params.posLimit) : UintToArith256(params.powLimit);

    const CBlockIndex* lastPowOrPosBlock = pindexLast;

    while (lastPowOrPosBlock != nullptr && lastPowOrPosBlock->IsProofOfStake() != is_proof_of_stake) {
        lastPowOrPosBlock = lastPowOrPosBlock->GetAncestor(lastPowOrPosBlock->nHeight - 1);
    }

     if (lastPowOrPosBlock == nullptr) {
        return nTargetLimit.GetCompact();
    }

    const CBlockIndex* lastLastPowOrPosBlock = lastPowOrPosBlock->GetAncestor(lastPowOrPosBlock->nHeight -1);
    while (lastLastPowOrPosBlock != nullptr && lastLastPowOrPosBlock->IsProofOfStake() != is_proof_of_stake) {
        lastLastPowOrPosBlock = lastLastPowOrPosBlock->GetAncestor(lastLastPowOrPosBlock->nHeight - 1);
    }

    if (lastLastPowOrPosBlock == nullptr) {
        return nTargetLimit.GetCompact();
    }

    // Limit adjustment step
    const int64_t nActualTimespan = lastPowOrPosBlock->GetBlockTime() - lastLastPowOrPosBlock->GetBlockTime();
    const int64_t nTargetTimespan = 960;             // 16 minutes
    const int64_t nInterval = nTargetTimespan / 256; // 3.75 -> 3

    const int64_t nTargetSpacing = 256;
    int64_t nActualSpacing = nActualTimespan > 0 ? nActualTimespan : nTargetSpacing;

    if (nActualSpacing > nTargetSpacing * 10)
        nActualSpacing = nTargetSpacing * 10;


    // Retarget
    arith_uint256 bnNew;
    bnNew.SetCompact(lastPowOrPosBlock->nBits);

    bnNew *= (nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing;
    bnNew /= (nInterval + 1) * nTargetSpacing;

    if (bnNew > nTargetLimit || bnNew <= 0)
        bnNew = nTargetLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

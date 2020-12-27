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

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const bool is_target_requested_for_pos, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    if (params.fPowPosNoRetargeting)
        return pindexLast->nBits;

    const CBlockIndex* lastPowOrPosBlock = pindexLast;

    // branch away here, 4 blocks after the ratchet  has activated. For comparison: StakeValidator.cs, line 144 ff.
    if (params.IsPosPowRatchetActiveAtHeight(pindexLast->nHeight - 4)) {
        const bool is_pindexLast_pos = pindexLast->IsProofOfStake();
        if (is_pindexLast_pos && pindexLast->nHeight % 2 != 0 || !is_pindexLast_pos && pindexLast->nHeight % 2 == 0)
            assert(false); // Misconfiguration: When the ratchet is active for a height, the convention that PoS block heights are even numbers, must be met.

        return GetNextRatchetTargetRequired(pindexLast, is_pindexLast_pos, is_target_requested_for_pos, params);
    }

    const arith_uint256 nTargetLimit = is_target_requested_for_pos ? UintToArith256(params.posLimit) : UintToArith256(params.powLimit);

    while (lastPowOrPosBlock != nullptr && lastPowOrPosBlock->IsProofOfStake() != is_target_requested_for_pos) {
        lastPowOrPosBlock = lastPowOrPosBlock->GetAncestor(lastPowOrPosBlock->nHeight - 1);
    }

    if (lastPowOrPosBlock == nullptr) {
        return nTargetLimit.GetCompact();
    }

    const CBlockIndex* lastLastPowOrPosBlock = lastPowOrPosBlock->GetAncestor(lastPowOrPosBlock->nHeight - 1);
    while (lastLastPowOrPosBlock != nullptr && lastLastPowOrPosBlock->IsProofOfStake() != is_target_requested_for_pos) {
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

unsigned int GetNextRatchetTargetRequired(const CBlockIndex* pindexLast, const bool is_pindexLast_pos, const bool is_target_requested_for_pos, const Consensus::Params& params)
{
    const CBlockIndex* lastPowPosBlock = pindexLast;

    // The caller passes an argument, whether a PoS or PoW Target is requested.
    if (is_target_requested_for_pos) {
        // Starting point will be the last PoS block.
        if (!is_pindexLast_pos) {
            // The previous block is guaranteed to be a PoS block, due to the offset of 2 to the ratchet activation height
            // and the precondition check when calling this from StakeValidator.
            lastPowPosBlock = lastPowPosBlock->pprev;
        }

        // We are passing in a PoS block!
        return GetNextPosTargetRequired(lastPowPosBlock, params);
    }

    // Starting point will be the last PoW block.
    if (is_pindexLast_pos) {
        // The previous block is guaranteed to be a PoW block, due to the offset of 2 to the ratchet activation height
        // and the precondition check when calling this from StakeValidator.
        lastPowPosBlock = lastPowPosBlock->pprev;
    }

    // We are passing in a PoW block!
    return GetNextPowTargetRequired(lastPowPosBlock, params);
}

unsigned int GetNextPosTargetRequired(const CBlockIndex* pindexLastPos, const Consensus::Params& params)
{
    // We'll need to go back 2 blocks, to calculate the time delta. We can only do that if the ratchet
    // was active 2 blocks before the current lastPosBlock. So if that's not possible, we simply return
    // the previous Target. Due to the precondition checks, we know it's a valid PoS Target.
    if (!params.IsPosPowRatchetActiveAtHeight(pindexLastPos->nHeight - 2) || params.fPowPosNoRetargeting) {
        return pindexLastPos->GetBlockHeader().nBits;
    }

    // we are sure this is a PoW block because of the precondition checks, which previous blocks have already passed
    const auto intermediate_pow_block = pindexLastPos->pprev;

    // we are sure this is a PoS block because of the precondition checks, which previous blocks have already passed
    const auto prevLastPosBlock = intermediate_pow_block->pprev;

    // the time in seconds the intermediate PoS block has used, which is must be hidden for the calculation
    const auto powGapSeconds = intermediate_pow_block->GetBlockHeader().nTime - prevLastPosBlock->GetBlockHeader().nTime;

    // add the powGapSeconds to the timestamp of the prevLastPosBlock, to compensate the time it took to create the PoW block
    const auto adjustedPrevLastPowPosBlockTime = prevLastPosBlock->GetBlockHeader().nTime + powGapSeconds;

    // pass in adjustedPrevLastPowPosBlockTime instead of the timestamp of the second block, and continue as normal
    return CalculatePosRetarget(pindexLastPos->nTime, pindexLastPos->GetBlockHeader().nBits, adjustedPrevLastPowPosBlockTime, params);
}

unsigned int CalculatePosRetarget(uint32_t lastPosBlockTime, uint32_t lastPosBlockBits, uint32_t previousPosBlockTime, const Consensus::Params& params)
{
    const auto target_spacing = params.nPowTargetSpacing;          // = 256
    auto actual_spacing = lastPosBlockTime - previousPosBlockTime; // this is never 0 or negative because that's a consensus rule

    // Limit the adjustment step by capping input values that are far from the average.
    if (actual_spacing > target_spacing * 4) // if the spacing was > 1024 seconds, pretend is was 1024 seconds
        actual_spacing = target_spacing * 4;
    if (actual_spacing < target_spacing / 4) // if the spacing was < 64 seconds, pretend is was 64 seconds
        actual_spacing = target_spacing / 4;

    // To reduce the impact of randomness, the actualSpacing's weight is reduced to 1/32th (instead of 1/2). This creates
    // similar results like using 32-period average.
    // The problem with random spacing values is that they frequently lead to difficult adjustments in the wrong direction,
    // when the sample size is as low as 1.
    // The results with 1/2 were: PoS block ETA seconds: Average: 351, Median: 165. But average and median should have been 256 seconds.
    const auto numerator = 31 * target_spacing + actual_spacing;
    const auto denominator = 32 * target_spacing;

    arith_uint256 bnNew;
    bnNew.SetCompact(lastPosBlockBits);
    bnNew *= numerator;
    bnNew /= denominator;

    const arith_uint256 bnPosLimit = UintToArith256(params.posLimit);

    if (bnNew > bnPosLimit)
        bnNew = bnPosLimit;

    return bnNew.GetCompact();
}

unsigned int GetNextPowTargetRequired(const CBlockIndex* pindexLastPow, const Consensus::Params& params)
{
    // Only change once per difficulty adjustment interval
    if ((int64_t(pindexLastPow->nHeight) + 1) % params.DifficultyAdjustmentInterval() != 0) {
        if (params.fPowAllowMinDifficultyBlocks) {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2 * TargetSpacing.TotalSeconds,
            // then allow mining of a min-difficulty block.
            if (pindexLastPow->nTime > pindexLastPow->nTime + params.nPowTargetSpacing * 2)
                return UintToArith256(params.powLimit).GetCompact();
            else {
                // Return the last non-special-min-difficulty-rules-block
                auto pindex = pindexLastPow;
                while (pindex->pprev != nullptr && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->GetBlockHeader().nBits == UintToArith256(params.powLimit).GetCompact())
                    pindex = pindex->pprev;
                return pindex->GetBlockHeader().nBits;
            }
        }

        // Not changing the Target means we return the previous PoW Target.
        return pindexLastPow->GetBlockHeader().nBits;
    }

    // We'll also not adjust the difficulty, if the ratchet wasn't active at least 2x difficultyAdjustmentInterval + 4 blocks.
    auto start = (params.RatchetHeight + 2 * params.DifficultyAdjustmentInterval() + 4);
    if (pindexLastPow->nHeight < start)
        return pindexLastPow->GetBlockHeader().nBits;

    // Define the amount of PoW blocks used to calculate the average, and for the sake of logic,
    // don't repeat Bitcoin's off-by one error.
    const auto amount_of_pow_blocks = params.DifficultyAdjustmentInterval();

    auto powBlockIterator = pindexLastPow;
    auto pow_block_count = 0;
    auto pos_gaps = 0u;
    auto powIntervalsIncPosSum = 0u;

    while (pow_block_count < amount_of_pow_blocks) {
        // we are sure this is a Pos block because of the precondition checks, which previous blocks have already passed
        const auto intermediate_pos_block = powBlockIterator->pprev;

        // we are sure this is a Pow block because of the precondition checks, which previous blocks have already passed
        const auto prev_last_pow_block = intermediate_pos_block->pprev;

        // the time in seconds the intermediate PoS block has used, which is must be hidden for the calculation
        const auto pos_gap_seconds = intermediate_pos_block->GetBlockHeader().nTime - prev_last_pow_block->GetBlockHeader().nTime;
        pos_gaps += pos_gap_seconds;

        const auto grossPowSeconds = powBlockIterator->GetBlockHeader().nTime - prev_last_pow_block->GetBlockHeader().nTime;
        powIntervalsIncPosSum += grossPowSeconds;

        // update the iterator
        powBlockIterator = prev_last_pow_block;

        // update the counter
        pow_block_count++;
    }

    const auto powActualTimeSpanIncPos = pindexLastPow->GetBlockHeader().nTime - powBlockIterator->GetBlockHeader().nTime;

    assert(pow_block_count == amount_of_pow_blocks);
    assert(powIntervalsIncPosSum == powActualTimeSpanIncPos);

    const auto first_pow_block_header_time_except_gaps = pindexLastPow->GetBlockHeader().nTime - powActualTimeSpanIncPos + pos_gaps;

    // Finally, we use the normal Bitcoin PoW Target calculation.
    return CalculateNextWorkRequired(pindexLastPow, first_pow_block_header_time_except_gaps, params);
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

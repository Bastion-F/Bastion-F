# Bastion-256 Specification

## Overview
Bastion-256 is an ARX-based stream cipher using a 256-bit key and
32-byte block function.

## Parameters
- Key size: 256 bits
- Nonce size: 128 bits
- Block size: 256 bits
- Rounds: 72

## Construction
- Keystream generator (CTR-like mode)
- Block function based on Add-Rotate-XOR
- No S-boxes, no table lookups

## Round Function
Each round consists of:
1. Key addition
2. Pairwise ARX mixing
3. Word permutation

## Key Schedule
Round keys are derived linearly from the master key using a rotating index
and round constants.

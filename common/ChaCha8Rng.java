package common;

import org.apache.commons.math3.random.AbstractRandomGenerator;

/**
 * ChaCha8-based PRNG matching Rust's rand_chacha::ChaCha8Rng exactly.
 *
 * This implementation mirrors:
 *   - rand_core::SeedableRng::seed_from_u64  (PCG32-based key derivation)
 *   - ChaCha8 block cipher (8 rounds = 4 double-rounds)
 *   - BlockRng buffer management (64 x u32 = 4 keystream blocks)
 *   - rand::Rng::gen::<f64>()  (53-bit mantissa from u64)
 *   - rand::Rng::gen_range(0..bound)  (Lemire's method for u64)
 *
 * All outputs will be bit-identical to Rust's ChaCha8Rng for a given seed.
 */
public class ChaCha8Rng extends AbstractRandomGenerator {

    // ChaCha constants ("expand 32-byte k")
    private static final int CONST_0 = 0x61707865;
    private static final int CONST_1 = 0x3320646e;
    private static final int CONST_2 = 0x79622d32;
    private static final int CONST_3 = 0x6b206574;

    // 256-bit key as 8 x int
    private final int[] key = new int[8];
    // 64-bit block counter (blocks produced so far)
    private long blockCounter = 0;
    // Output buffer: 4 ChaCha blocks x 16 words = 64 words (256 bytes)
    private final int[] buffer = new int[64];
    // Current index into buffer (starts exhausted  ->  first call triggers generate)
    private int bufferIndex = 64;

    /**
     * Construct a ChaCha8Rng from a 64-bit seed.
     * Matches Rust's {@code ChaCha8Rng::seed_from_u64(seed)}.
     */
    public ChaCha8Rng(long seed) {
        byte[] keyBytes = seedFromU64(seed);
        for (int i = 0; i < 8; i++) {
            key[i] = littleEndian32(keyBytes, i * 4);
        }
    }

    // -- PCG32-based seed expansion (matches rand_core::SeedableRng) ----------

    /**
     * Expand a 64-bit seed into a 32-byte ChaCha key.
     * Uses the PCG32 output function, matching rand_core's default
     * {@code seed_from_u64} implementation exactly.
     */
    private static byte[] seedFromU64(long seed) {
        final long MUL = 6364136223846793005L;
        final long INC = -6812164046247290893L; // = 11634580027462260723 unsigned

        byte[] result = new byte[32];
        long state = seed;
        for (int chunk = 0; chunk < 8; chunk++) {
            // Advance state FIRST, then apply PCG output on new state
            // (rand_core 0.6.x: "get away from the input value")
            state = state * MUL + INC;
            int xorshifted = (int) (((state >>> 18) ^ state) >>> 27);
            int rot = (int) (state >>> 59);
            int value = (xorshifted >>> rot) | (xorshifted << ((32 - rot) & 31));
            // Little-endian
            result[chunk * 4]     = (byte)  value;
            result[chunk * 4 + 1] = (byte) (value >>> 8);
            result[chunk * 4 + 2] = (byte) (value >>> 16);
            result[chunk * 4 + 3] = (byte) (value >>> 24);
        }
        return result;
    }

    private static int littleEndian32(byte[] bs, int off) {
        return (bs[off] & 0xff)
                | ((bs[off + 1] & 0xff) << 8)
                | ((bs[off + 2] & 0xff) << 16)
                | ((bs[off + 3] & 0xff) << 24);
    }

    // -- ChaCha8 core --------------------------------------------------------

    /**
     * Generate 4 ChaCha8 keystream blocks (256 bytes = 64 ints) into the buffer.
     * Increments the block counter by 4.
     */
    private void generateBlocks() {
        for (int block = 0; block < 4; block++) {
            long ctr = blockCounter + block;
            int ctrLo = (int) ctr;
            int ctrHi = (int) (ctr >>> 32);

            // Initial state
            int x0 = CONST_0, x1 = CONST_1, x2 = CONST_2, x3 = CONST_3;
            int x4 = key[0], x5 = key[1], x6 = key[2], x7 = key[3];
            int x8 = key[4], x9 = key[5], x10 = key[6], x11 = key[7];
            int x12 = ctrLo, x13 = ctrHi, x14 = 0, x15 = 0;

            // 4 double-rounds = ChaCha8
            for (int r = 0; r < 4; r++) {
                // Column rounds
                x0 += x4; x12 ^= x0; x12 = Integer.rotateLeft(x12, 16);
                x8 += x12; x4 ^= x8; x4 = Integer.rotateLeft(x4, 12);
                x0 += x4; x12 ^= x0; x12 = Integer.rotateLeft(x12, 8);
                x8 += x12; x4 ^= x8; x4 = Integer.rotateLeft(x4, 7);

                x1 += x5; x13 ^= x1; x13 = Integer.rotateLeft(x13, 16);
                x9 += x13; x5 ^= x9; x5 = Integer.rotateLeft(x5, 12);
                x1 += x5; x13 ^= x1; x13 = Integer.rotateLeft(x13, 8);
                x9 += x13; x5 ^= x9; x5 = Integer.rotateLeft(x5, 7);

                x2 += x6; x14 ^= x2; x14 = Integer.rotateLeft(x14, 16);
                x10 += x14; x6 ^= x10; x6 = Integer.rotateLeft(x6, 12);
                x2 += x6; x14 ^= x2; x14 = Integer.rotateLeft(x14, 8);
                x10 += x14; x6 ^= x10; x6 = Integer.rotateLeft(x6, 7);

                x3 += x7; x15 ^= x3; x15 = Integer.rotateLeft(x15, 16);
                x11 += x15; x7 ^= x11; x7 = Integer.rotateLeft(x7, 12);
                x3 += x7; x15 ^= x3; x15 = Integer.rotateLeft(x15, 8);
                x11 += x15; x7 ^= x11; x7 = Integer.rotateLeft(x7, 7);

                // Diagonal rounds
                x0 += x5; x15 ^= x0; x15 = Integer.rotateLeft(x15, 16);
                x10 += x15; x5 ^= x10; x5 = Integer.rotateLeft(x5, 12);
                x0 += x5; x15 ^= x0; x15 = Integer.rotateLeft(x15, 8);
                x10 += x15; x5 ^= x10; x5 = Integer.rotateLeft(x5, 7);

                x1 += x6; x12 ^= x1; x12 = Integer.rotateLeft(x12, 16);
                x11 += x12; x6 ^= x11; x6 = Integer.rotateLeft(x6, 12);
                x1 += x6; x12 ^= x1; x12 = Integer.rotateLeft(x12, 8);
                x11 += x12; x6 ^= x11; x6 = Integer.rotateLeft(x6, 7);

                x2 += x7; x13 ^= x2; x13 = Integer.rotateLeft(x13, 16);
                x8 += x13; x7 ^= x8; x7 = Integer.rotateLeft(x7, 12);
                x2 += x7; x13 ^= x2; x13 = Integer.rotateLeft(x13, 8);
                x8 += x13; x7 ^= x8; x7 = Integer.rotateLeft(x7, 7);

                x3 += x4; x14 ^= x3; x14 = Integer.rotateLeft(x14, 16);
                x9 += x14; x4 ^= x9; x4 = Integer.rotateLeft(x4, 12);
                x3 += x4; x14 ^= x3; x14 = Integer.rotateLeft(x14, 8);
                x9 += x14; x4 ^= x9; x4 = Integer.rotateLeft(x4, 7);
            }

            // Add original state
            int off = block * 16;
            buffer[off]      = x0  + CONST_0;
            buffer[off + 1]  = x1  + CONST_1;
            buffer[off + 2]  = x2  + CONST_2;
            buffer[off + 3]  = x3  + CONST_3;
            buffer[off + 4]  = x4  + key[0];
            buffer[off + 5]  = x5  + key[1];
            buffer[off + 6]  = x6  + key[2];
            buffer[off + 7]  = x7  + key[3];
            buffer[off + 8]  = x8  + key[4];
            buffer[off + 9]  = x9  + key[5];
            buffer[off + 10] = x10 + key[6];
            buffer[off + 11] = x11 + key[7];
            buffer[off + 12] = x12 + ctrLo;
            buffer[off + 13] = x13 + ctrHi;
            buffer[off + 14] = x14;           // nonce = 0
            buffer[off + 15] = x15;           // nonce = 0
        }
        blockCounter += 4;
        bufferIndex = 0;
    }

    // -- Low-level output ----------------------------------------------------

    /** Next u32 from the ChaCha8 stream (matches Rust BlockRng::next_u32). */
    public int nextU32() {
        if (bufferIndex >= 64) {
            generateBlocks();
        }
        return buffer[bufferIndex++];
    }

    /** Next u64, little-endian pair of u32 (matches Rust BlockRng::next_u64). */
    public long nextU64() {
        long lo = Integer.toUnsignedLong(nextU32());
        long hi = Integer.toUnsignedLong(nextU32());
        return (hi << 32) | lo;
    }

    // -- Public API matching Rust's rand::Rng trait --------------------------

    /**
     * Random f64 in [0, 1).
     * Matches Rust's {@code rng.gen::<f64>()}: takes 53 high bits of u64.
     */
    @Override
    public double nextDouble() {
        long u = nextU64();
        long fraction = u >>> 11; // 53 bits
        return fraction * 0x1.0p-53; // 2^-53
    }

    /**
     * Random int in [0, bound).
     * Matches Rust's {@code rng.gen_range(0..bound)} for usize (u64) via
     * Lemire's method with a conservative approximation zone.
     *
     * Rust's rand 0.8.5 sample_single_inclusive uses:
     *   zone = (range << range.leading_zeros()) - 1
     *   accept if lo <= zone
     * This avoids an expensive modulus but rejects slightly more values.
     */
    @Override
    public int nextInt(int bound) {
        if (bound <= 0) {
            throw new IllegalArgumentException("bound must be positive: " + bound);
        }
        long range = Integer.toUnsignedLong(bound);
        // Conservative approximation matching Rust's sample_single_inclusive
        long zone = (range << Long.numberOfLeadingZeros(range)) - 1;
        while (true) {
            long v = nextU64();
            long hi = unsignedMultiplyHigh(v, range);
            long lo = v * range; // lower 64 bits of v x range
            if (Long.compareUnsigned(lo, zone) <= 0) {
                return (int) hi;
            }
        }
    }

    // -- 128-bit unsigned multiply (upper 64 bits) ----------------------------

    /**
     * Compute the upper 64 bits of the unsigned 128-bit product a x b.
     * Portable pure-Java implementation (no Java 9+ Math.multiplyHigh needed).
     */
    private static long unsignedMultiplyHigh(long a, long b) {
        long aLo = a & 0xFFFFFFFFL;
        long aHi = a >>> 32;
        long bLo = b & 0xFFFFFFFFL;
        long bHi = b >>> 32;

        long p0 = aLo * bLo;
        long p1 = aLo * bHi;
        long p2 = aHi * bLo;
        long p3 = aHi * bHi;

        long mid = (p0 >>> 32) + (p1 & 0xFFFFFFFFL) + (p2 & 0xFFFFFFFFL);
        return p3 + (p1 >>> 32) + (p2 >>> 32) + (mid >>> 32);
    }

    // -- RandomGenerator interface (remaining methods) ------------------------

    @Override
    public void setSeed(long seed) {
        // Re-init from seed. Called by AbstractRandomGenerator constructor.
        // Our state is set in constructor, so this is a no-op if called early.
    }

    @Override
    public float nextFloat() {
        return (float) nextDouble();
    }

    @Override
    public int nextInt() {
        return nextU32();
    }

    @Override
    public long nextLong() {
        return nextU64();
    }

    @Override
    public boolean nextBoolean() {
        return (nextU32() & 1) != 0;
    }

    @Override
    public void nextBytes(byte[] bytes) {
        int i = 0;
        while (i < bytes.length) {
            int word = nextU32();
            for (int j = 0; j < 4 && i < bytes.length; j++, i++) {
                bytes[i] = (byte) (word >>> (j * 8));
            }
        }
    }
}

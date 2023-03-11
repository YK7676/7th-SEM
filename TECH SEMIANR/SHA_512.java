import java.math.BigInteger;

public class SHA_512 {

    private static final int BLOCK_SIZE = 128;
    private static final int DIGEST_LENGTH = 64;
    private static final long[] INITIAL_HASH = {
            0x6a09e667f3bcc908L,
            0xbb67ae8584caa73bL,
            0x3c6ef372fe94f82bL,
            0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L,
            0x9b05688c2b3e6c1fL,
            0x1f83d9abfb41bd6bL,
            0x5be0cd19137e2179L
    };

    private static final long[] K = {
            0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
            0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
            0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
            0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
            0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
            0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
            0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
            0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
            0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
            0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL, 
            0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L, 
            0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L, 
            0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L, 
            0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L, 
            0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL, 
            0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL, 
            0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L, 
            0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL, 
            0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL, 
            0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
            
    };

    private byte[] data;
    private int length;
    private long[] hash;
    private long[] block;
    private int blockIndex;
    private long byteCount;

    public SHA512() {
        this.data = new byte[BLOCK_SIZE];
        this.hash = INITIAL_HASH.clone();
        this.block = new long[80];
    }

    public void update(byte[] input) {
        for (int i = 0; i < input.length; i++) {
            data[blockIndex++] = input[i];
            if (blockIndex == BLOCK_SIZE) {
                processBlock();
            }
        }
        byteCount += input.length;
    }

    public byte[] digest() {
        pad();
        byte[] digest = new byte[DIGEST_LENGTH];
        for (int i = 0; i < 8; i++) {
            long h = hash[i];
            for (int j = 0; j < 8; j++) {
                digest[i * 8 + j] = (byte)(h >>> (56 - j * 8));
            }
        }
        reset();
        return digest;
    }

    private void processBlock() {
        for (int i = 0; i < 16; i++) {
            block[i] = ((long)(data[i * 8] & 0xff) << 56)
                    | ((long)(data[i * 8 + 1] & 0xff) << 48)
                    | ((long)(data[i * 8 + 2] & 0xff) << 40)
                    | ((long)(data[i * 8 + 3] & 0xff) << 32)
                    | ((long)(data[i * 8 + 4] & 0xff) << 24)
                    | ((long)(data[i * 8 + 5] & 0xff) << 16)
                    | ((long)(data[i * 8 + 6] & 0xff) << 8)
                    | ((long)(data[i * 8 + 7] & 0xff));
        }
        for (int i = 16; i < 80; i++) {
            block[i] = block[i - 16]
                    + sigma1(block[i - 2])
                    + block[i - 7]
                    + sigma0(block[i - 15]);
        }
        long a = hash[0];
        long b = hash[1];
        long c = hash[2];
        long d = hash[3];
        long e = hash[4];
        long f = hash[5];
        long g = hash[6];
        long h = hash[7];
        for (int i = 0; i < 80; i++) {
            long t1 = h + Sum1(e) + Ch(e, f, g) + K[i] + block[i];
            long t2 = Sum0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
        blockIndex = 0;
    }

    private void pad() {
        data[blockIndex++] = (byte)0x80;
        if (blockIndex > 112) {
            while (blockIndex < BLOCK_SIZE) {
                data[blockIndex++] = 0;
            }
            processBlock();
        }
        while (blockIndex < 112) {
            data[blockIndex++] = 0;
        }
        byteCount *= 8;
        for (int i = 0; i < 8; i++) {
            data[            blockIndex++] = (byte)(byteCount >>> (56 - i * 8));
        }
        processBlock();
    }

    private void reset() {
        data = new byte[BLOCK_SIZE];
        hash = INITIAL_HASH.clone();
        block = new long[80];
        blockIndex = 0;
        byteCount = 0;
    }

    private long Sum0(long x) {
        return (x >>> 28 | x `oaicite:{"index":0,"invalid_reason":"Malformed citation << 36) ^ (x >>>"}` 34 | x `oaicite:{"index":1,"invalid_reason":"Malformed citation << 30) ^ (x >>>"}` 39 | x `oaicite:{"index":2,"invalid_reason":"Malformed citation << 25);\n    }\n\n    private long Sum1(long x) {\n        return (x >>>"}` 14 | x `oaicite:{"index":3,"invalid_reason":"Malformed citation << 50) ^ (x >>>"}` 18 | x `oaicite:{"index":4,"invalid_reason":"Malformed citation << 46) ^ (x >>>"}` 41 | x `oaicite:{"index":5,"invalid_reason":"Malformed citation << 23);\n    }\n\n    private long sigma0(long x) {\n        return (x >>>"}` 1 | x `oaicite:{"index":6,"invalid_reason":"Malformed citation << 63) ^ (x >>>"}` 8 | x `oaicite:{"index":7,"invalid_reason":"Malformed citation << 56) ^ (x >>> 7);\n    }\n\n    private long sigma1(long x) {\n        return (x >>>"}` 19 | x `oaicite:{"index":8,"invalid_reason":"Malformed citation << 45) ^ (x >>>"}` 61 | x `oaicite:{"index":9,"invalid_reason":"Malformed citation << 3) ^ (x >>>"}` 6);
    }

    private long Ch(long x, long y, long z) {
        return (x & y) ^ (~x & z);
    }

    private long Maj(long x, long y, long z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
}



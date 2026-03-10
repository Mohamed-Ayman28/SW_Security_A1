
public class DESEncryption {

    private static final int[] IP = {
            58,50,42,34,26,18,10,2,
            60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6,
            64,56,48,40,32,24,16,8,
            57,49,41,33,25,17, 9,1,
            59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,
            63,55,47,39,31,23,15,7
    };

    private static final int[] IP_INV = {
            40,8,48,16,56,24,64,32,
            39,7,47,15,55,23,63,31,
            38,6,46,14,54,22,62,30,
            37,5,45,13,53,21,61,29,
            36,4,44,12,52,20,60,28,
            35,3,43,11,51,19,59,27,
            34,2,42,10,50,18,58,26,
            33,1,41, 9,49,17,57,25
    };

    private static final int[] E = {
            32,1,2,3,4,5,
            4,5,6,7,8,9,
            8,9,10,11,12,13,
            12,13,14,15,16,17,
            16,17,18,19,20,21,
            20,21,22,23,24,25,
            24,25,26,27,28,29,
            28,29,30,31,32,1
    };

    private static final int[] P = {
            16,7,20,21,29,12,28,17,
            1,15,23,26,5,18,31,10,
            2,8,24,14,32,27,3,9,
            19,13,30,6,22,11,4,25
    };

    private static final int[] PC1 = {
            57,49,41,33,25,17,9,
            1,58,50,42,34,26,18,
            10,2,59,51,43,35,27,
            19,11,3,60,52,44,36,
            63,55,47,39,31,23,15,
            7,62,54,46,38,30,22,
            14,6,61,53,45,37,29,
            21,13,5,28,20,12,4
    };

    private static final int[] PC2 = {
            14,17,11,24,1,5,
            3,28,15,6,21,10,
            23,19,12,4,26,8,
            16,7,27,20,13,2,
            41,52,31,37,47,55,
            30,40,51,45,33,48,
            44,49,39,56,34,53,
            46,42,50,36,29,32
    };

    private static final int[] SHIFTS = {
            1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
    };

    private static final int[][][] S_BOXES = {
            // S1
            {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                    {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
            // S2
            {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                    {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                    {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                    {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
            // S3
            {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                    {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                    {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                    {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
            // S4
            {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                    {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                    {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
            // S5
            {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                    {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                    {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                    {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
            // S6
            {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                    {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                    {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                    {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
            // S7
            {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                    {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                    {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
            // S8
            {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
    };

    private static int[] permute(int[] bits, int[] table) {
        int[] out = new int[table.length];
        for (int i = 0; i < table.length; i++)
            out[i] = bits[table[i] - 1];
        return out;
    }

    private static int[] longToBits(long val) {
        int[] bits = new int[64];
        for (int i = 63; i >= 0; i--) {
            bits[i] = (int)(val & 1L);
            val >>= 1;
        }
        return bits;
    }

    private static long bitsToLong(int[] bits) {
        long val = 0;
        for (int b : bits) val = (val << 1) | b;
        return val;
    }

    private static String bitsToHex(int[] bits) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bits.length; i += 4) {
            int nibble = (bits[i]<<3)|(bits[i+1]<<2)|(bits[i+2]<<1)|bits[i+3];
            sb.append(Integer.toHexString(nibble).toUpperCase());
        }
        return sb.toString();
    }

    private static String longToHex(long val) {
        String hex = Long.toHexString(val).toUpperCase();
        while (hex.length() < 16) hex = "0" + hex;
        return hex;
    }

    private static String pad(String s, int width) {
        while (s.length() < width) s = s + " ";
        return s;
    }

    private static int[] xor(int[] a, int[] b) {
        int[] out = new int[a.length];
        for (int i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
        return out;
    }

    private static int[] leftShift(int[] bits, int n) {
        int len = bits.length;
        int[] out = new int[len];
        for (int i = 0; i < len; i++)
            out[i] = bits[(i + n) % len];
        return out;
    }

    private static int[] slice(int[] bits, int from, int to) {
        int[] out = new int[to - from];
        System.arraycopy(bits, from, out, 0, to - from);
        return out;
    }

    private static int[] concat(int[] a, int[] b) {
        int[] out = new int[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }



    private static int[][] generateSubkeys(long keyLong) {

        int[] keyBits = longToBits(keyLong);
        System.out.println("  Original 64-bit key  : " + longToHex(keyLong));
        System.out.println("  Bits   : " + bitsToHex(keyBits));

        // PC-1: 64 → 56 bits
        int[] permKey = permute(keyBits, PC1);
        System.out.println("\n  After PC-1 (56 bits) : " + bitsToHex(permKey));

        int[] C = slice(permKey, 0, 28);
        int[] D = slice(permKey, 28, 56);

        int[][] subkeys = new int[16][];
        System.out.println();
        System.out.println("  " + pad("Round", 7) + pad("C (hex)", 9) + pad("D (hex)", 9) + "Subkey K_i");
        System.out.println();

        for (int round = 0; round < 16; round++) {
            C = leftShift(C, SHIFTS[round]);
            D = leftShift(D, SHIFTS[round]);
            int[] CD = concat(C, D);
            subkeys[round] = permute(CD, PC2);

            System.out.println("  " + pad("K" + (round + 1), 7) + pad(bitsToHex(C), 9) + pad(bitsToHex(D), 9) + bitsToHex(subkeys[round]));
        }
        System.out.println();
        return subkeys;
    }

    private static int[] feistel(int[] R, int[] K, int round) {
        // 1. Expand R: 32 → 48 bits
        int[] expanded = permute(R, E);

        // 2. XOR with subkey
        int[] xored = xor(expanded, K);

        // 3. S-box substitution: 48 → 32 bits
        int[] sboxOut = new int[32];
        for (int i = 0; i < 8; i++) {
            int base = i * 6;
            int row = (xored[base] << 1) | xored[base + 5];
            int col = (xored[base+1]<<3)|(xored[base+2]<<2)
                    |(xored[base+3]<<1)| xored[base+4];
            int val = S_BOXES[i][row][col];
            for (int b = 3; b >= 0; b--) {
                sboxOut[i * 4 + (3 - b)] = (val >> b) & 1;
            }
        }

        // 4. Permutation P
        return permute(sboxOut, P);
    }

    public static long encrypt(long plaintext, long key) {
        int[][] subkeys = generateSubkeys(key);

        System.out.println("  DES ENCRYPTION");
        System.out.println();
        System.out.println("  Plaintext  : " + longToHex(plaintext));
        System.out.println("  Key        : " + longToHex(key));
        System.out.println();

        // ── Initial Permutation ──────────────────────
        int[] ptBits = longToBits(plaintext);
        int[] ipBits = permute(ptBits, IP);
        System.out.println(" Initial Permutation (IP)");
        System.out.println(" Input  : " + bitsToHex(ptBits));
        System.out.println(" Output : " + bitsToHex(ipBits));
        System.out.println();

        int[] L = slice(ipBits, 0, 32);
        int[] R = slice(ipBits, 32, 64);
        System.out.println("  L0 = " + bitsToHex(L) + "    R0 = " + bitsToHex(R));
        System.out.println();

        System.out.println(" 16 Feistel Rounds");
        System.out.println(pad("Round", 8) + pad("K_i", 12) + pad("f(R,K)", 12) + pad("L_new", 14) + pad("R_new", 12));
        System.out.println();

        for (int i = 0; i < 16; i++) {
            int[] fResult = feistel(R, subkeys[i], i);
            int[] newL = R;
            int[] newR = xor(L, fResult);

            System.out.println(pad("R" + (i + 1), 8) + pad(bitsToHex(subkeys[i]), 12) + pad(bitsToHex(fResult), 12) + pad(bitsToHex(newL), 14) + pad(bitsToHex(newR), 12));

            L = newL;
            R = newR;
        }
        System.out.println();

        // Pre-output: swap L and R
        int[] preOutput = concat(R, L);
        System.out.println("  Pre-output (R16 ++ L16) : " + bitsToHex(preOutput));
        System.out.println();

        // ── Final Permutation ────────────────────────
        int[] cipherBits = permute(preOutput, IP_INV);
        long ciphertext = bitsToLong(cipherBits);

        System.out.println("Final Permutation");
        System.out.println("Input  : " + bitsToHex(preOutput));
        System.out.println("Output : " + bitsToHex(cipherBits));
        System.out.println();
        System.out.println("  Ciphertext : " + longToHex(ciphertext));

        return ciphertext;
    }

    private static long[] readFromJson(String filename) throws Exception {
        java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(filename));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line.trim());
        reader.close();

        String content = sb.toString();
        long key       = parseJsonHexValue(content, "key");
        long plaintext = parseJsonHexValue(content, "plaintext");
        return new long[]{key, plaintext};
    }


    private static long parseJsonHexValue(String json, String fieldName) {
        String search = "\"" + fieldName + "\"";
        int fieldIndex = json.indexOf(search);
        if (fieldIndex == -1) throw new RuntimeException("Field not found in JSON: " + fieldName);

        int colonIndex = json.indexOf(":", fieldIndex);
        int openQuote  = json.indexOf("\"", colonIndex);
        int closeQuote = json.indexOf("\"", openQuote + 1);

        String hexVal = json.substring(openQuote + 1, closeQuote).trim();
        return Long.parseUnsignedLong(hexVal, 16);
    }



    public static void main(String[] args) {
        long key =0, plaintext =0;

        if (args.length == 1) {

            String filename = args[0];
            try {
                long[] values;
                if (filename.endsWith(".json")) {
                    values = readFromJson(filename);
                    System.out.println("  Input loaded from JSON file: " + filename);
                }
                else {
                    System.out.println("  ERROR: Unsupported file type. Use a .json or .txt file.");
                    return;
                }
                key       = values[0];
                plaintext = values[1];
            } catch (Exception e) {
                System.out.println("  ERROR reading file: " + e.getMessage());
                return;
            }
        }

        System.out.println();


        long ciphertext = encrypt(plaintext, key);

        System.out.println();

        System.out.println(" Key        : " + longToHex(key));
        System.out.println(" Plaintext  : " + longToHex(plaintext));
        System.out.println(" Ciphertext : " + longToHex(ciphertext));
    }
}
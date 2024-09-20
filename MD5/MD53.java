import java.util.*;

public class MD53 {
    public static void main(String[] args) {
        Scanner scn = new Scanner(System.in);
        System.out.println("Input:");
        String input = scn.next();

        // Convert the input string to bytes
        byte[] message = input.getBytes();

        // Initialize variables
        int[] s = { 7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21 };
        int[] K = new int[64];
        for (int i = 0; i < 64; i++) {
            K[i] = (int) (long) (Math.abs(Math.sin(i + 1)) * (1L << 32));
        }
        int A = 0x67452301;
        int B = 0xEFCDAB89;
        int C = 0x98BADCFE;
        int D = 0x10325476;

        // Padding
        int originalLength = message.length;
        int paddingLength = (56 - originalLength % 64) % 64;
        int paddedLength = originalLength + paddingLength + 8;
        byte[] paddedMessage = new byte[paddedLength];
        System.arraycopy(message, 0, paddedMessage, 0, originalLength);
        paddedMessage[originalLength] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            paddedMessage[paddedLength - 8 + i] = (byte) ((originalLength * 8) >>> (8 * i));
        }

        // Process message in 16-word blocks
        for (int i = 0; i < paddedLength; i += 64) {
            int[] M = new int[16];
            for (int j = 0; j < 16; j++) {
                M[j] = (paddedMessage[i + 4 * j] & 0xFF)
                        | ((paddedMessage[i + 4 * j + 1] & 0xFF) << 8)
                        | ((paddedMessage[i + 4 * j + 2] & 0xFF) << 16)
                        | ((paddedMessage[i + 4 * j + 3] & 0xFF) << 24);
            }

            int AA = A;
            int BB = B;
            int CC = C;
            int DD = D;

            // Round 1
            for (int j = 0; j < 16; j++) {
                int F = (B & C) | ((~B) & D);
                int g = j;
                int temp = D;
                D = C;
                C = B;
                B += Integer.rotateLeft((A + F + K[j] + M[g]), s[j]);
                A = temp;
            }
            printIntermediateHash(A, B, C, D, 1);

            // Round 2
            for (int j = 0; j < 16; j++) {
                int F = (D & B) | ((~D) & C);
                int g = (5 * j + 1) % 16;
                int temp = D;
                D = C;
                C = B;
                B += Integer.rotateLeft((A + F + K[j + 16] + M[g]), s[j]);
                A = temp;
            }
            printIntermediateHash(A, B, C, D, 2);

            // Round 3
            for (int j = 0; j < 16; j++) {
                int F = B ^ C ^ D;
                int g = (3 * j + 5) % 16;
                int temp = D;
                D = C;
                C = B;
                B += Integer.rotateLeft((A + F + K[j + 32] + M[g]), s[j]);
                A = temp;
            }
            printIntermediateHash(A, B, C, D, 3);

            // Round 4
            for (int j = 0; j < 16; j++) {
                int F = C ^ (B | (~D));
                int g = (7 * j) % 16;
                int temp = D;
                D = C;
                C = B;
                B += Integer.rotateLeft((A + F + K[j + 48] + M[g]), s[j]);
                A = temp;
            }
            printIntermediateHash(A, B, C, D, 4);

            A += AA;
            B += BB;
            C += CC;
            D += DD;
        }

        // Final hash value
        byte[] hash = new byte[16];
        int count = 0;
        for (int i = 0; i < 4; i++) {
            hash[count++] = (byte) (A & 0xFF);
            hash[count++] = (byte) ((A >>> 8) & 0xFF);
            hash[count++] = (byte) ((A >>> 16) & 0xFF);
            hash[count++] = (byte) ((A >>> 24) & 0xFF);
            A = B;
            B = C;
            C = D;
            // D = 0; // This line seems unnecessary
        }

        // Print the hash value
        System.out.print("Hash value: ");
        for (byte b : hash) {
            System.out.printf("%02x", b);
        }
        System.out.println();
    }

    private static void printIntermediateHash(int A, int B, int C, int D, int round) {
        System.out.println("Round " + round + ": A = 0x" + Integer.toHexString(A) +
                ", B = 0x" + Integer.toHexString(B) +
                ", C = 0x" + Integer.toHexString(C) +
                ", D = 0x" + Integer.toHexString(D));
    }
}




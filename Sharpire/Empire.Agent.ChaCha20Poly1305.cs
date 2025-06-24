using System;
using System.Numerics;

namespace ChaChaEncryption
{
    public class ChaCha20
    {
        private const int ROUNDS = 20;

        private static uint Rotate(uint v, int c) => (v << c) | (v >> (32 - c));

        private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b; d ^= a; d = Rotate(d, 16);
            c += d; b ^= c; b = Rotate(b, 12);
            a += b; d ^= a; d = Rotate(d, 8);
            c += d; b ^= c; b = Rotate(b, 7);
        }

        public static void Encrypt(byte[] key, byte[] nonce, uint counter, byte[] input, byte[] output)
        {
            uint[] state = new uint[16];
            Buffer.BlockCopy(System.Text.Encoding.ASCII.GetBytes("expand 32-byte k"), 0, state, 0, 16);
            for (int i = 0; i < 8; i++) state[4 + i] = BitConverter.ToUInt32(key, i * 4);
            state[12] = counter;
            state[13] = BitConverter.ToUInt32(nonce, 0);
            state[14] = BitConverter.ToUInt32(nonce, 4);
            state[15] = BitConverter.ToUInt32(nonce, 8);

            byte[] block = new byte[64];
            for (int i = 0; i < input.Length; i += 64)
            {
                uint[] workingState = (uint[])state.Clone();
                for (int r = 0; r < ROUNDS; r += 2)
                {
                    // Column rounds
                    QuarterRound(ref workingState[0], ref workingState[4], ref workingState[8], ref workingState[12]);
                    QuarterRound(ref workingState[1], ref workingState[5], ref workingState[9], ref workingState[13]);
                    QuarterRound(ref workingState[2], ref workingState[6], ref workingState[10], ref workingState[14]);
                    QuarterRound(ref workingState[3], ref workingState[7], ref workingState[11], ref workingState[15]);

                    // Diagonal rounds
                    QuarterRound(ref workingState[0], ref workingState[5], ref workingState[10], ref workingState[15]);
                    QuarterRound(ref workingState[1], ref workingState[6], ref workingState[11], ref workingState[12]);
                    QuarterRound(ref workingState[2], ref workingState[7], ref workingState[8], ref workingState[13]);
                    QuarterRound(ref workingState[3], ref workingState[4], ref workingState[9], ref workingState[14]);
                }

                for (int j = 0; j < 16; j++)
                    workingState[j] += state[j];

                for (int j = 0; j < 16; j++)
                    Array.Copy(BitConverter.GetBytes(workingState[j]), 0, block, j * 4, 4);

                int len = Math.Min(64, input.Length - i);
                for (int j = 0; j < len; j++)
                    output[i + j] = (byte)(input[i + j] ^ block[j]);

                state[12]++;
            }
        }
    }

    public class Poly1305
    {
        private const int BLOCK_SIZE = 16;

        public static byte[] ComputeTag(byte[] msg, byte[] key)
        {
            BigInteger r = LoadAndClampR(key);
            BigInteger s = LoadLE(key, 16);
            BigInteger a = 0;
            for (int i = 0; i < msg.Length; i += BLOCK_SIZE)
            {
                int len = Math.Min(BLOCK_SIZE, msg.Length - i);
                byte[] block = new byte[BLOCK_SIZE + 1];
                Buffer.BlockCopy(msg, i, block, 0, len);
                block[len] = 0x01; // Pad bit
                BigInteger n = new BigInteger(block);
                a = ((a + n) * r) % BigInteger.Pow(2, 130) - 5;
            }

            a = (a + s) % BigInteger.Pow(2, 128);
            byte[] tag = a.ToByteArray();
            Array.Resize(ref tag, 16);
            return tag;
        }

        private static BigInteger LoadAndClampR(byte[] key)
        {
            byte[] r = new byte[16];
            Array.Copy(key, 0, r, 0, 16);

            r[3] &= 15; r[7] &= 15; r[11] &= 15; r[15] &= 15;
            r[4] &= 252; r[8] &= 252; r[12] &= 252;

            return new BigInteger(r);
        }

        private static BigInteger LoadLE(byte[] data, int offset)
        {
            byte[] tmp = new byte[16];
            Array.Copy(data, offset, tmp, 0, 16);
            return new BigInteger(tmp);
        }
    }

    public static class ChaCha20Poly1305
    {
        public static void Encrypt(byte[] key, byte[] nonce, byte[] plaintext, out byte[] ciphertext, out byte[] tag)
        {
            byte[] polyKey = new byte[64];
            ChaCha20.Encrypt(key, nonce, 0, new byte[64], polyKey);

            byte[] ciphertextOut = new byte[plaintext.Length];
            ChaCha20.Encrypt(key, nonce, 1, plaintext, ciphertextOut);

            tag = Poly1305.ComputeTag(ciphertextOut, polyKey);
            ciphertext = ciphertextOut;
        }

        public static bool Decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, out byte[] plaintext)
        {
            byte[] polyKey = new byte[64];
            ChaCha20.Encrypt(key, nonce, 0, new byte[64], polyKey);

            byte[] computedTag = Poly1305.ComputeTag(ciphertext, polyKey);
            if (!ConstantTimeEquals(computedTag, tag))
            {
                plaintext = null;
                return false; // Tag mismatch
            }

            plaintext = new byte[ciphertext.Length];
            ChaCha20.Encrypt(key, nonce, 1, ciphertext, plaintext);
            return true;
        }

        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }
    }
}

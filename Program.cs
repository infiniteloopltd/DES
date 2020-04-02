using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines; // Install-Package BouncyCastle -Version 1.8.5
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace DES
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("DES Encryption example");
            Console.WriteLine("----------------------");
            Console.WriteLine("Enter text to encrypt?");
            var plaintext = Console.ReadLine();
            Console.WriteLine("Enter an 8-Byte key?");
            var desKey = Console.ReadLine();
            var key = Encoding.ASCII.GetBytes(desKey ?? "12345678");
            var input = Encoding.ASCII.GetBytes(plaintext ?? "HELLO");
            var output = DES_Encrypt(input, key);
            var cipherText = BitConverter.ToString(output);
            Console.WriteLine("cipherText (hex):");
            Console.WriteLine(cipherText);
            var reversed = DES_Decrypt(key, output);
            var plainTextDecrypted = Encoding.ASCII.GetString(reversed);
            Console.WriteLine("Plain text:");
            Console.WriteLine(plainTextDecrypted);
            Console.ReadKey();
        }

        private static byte[] DES_Encrypt(byte[] input, byte[] key)
        {
            var engine = new DesEngine();
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine));
            cipher.Init(true, new KeyParameter(key));
            var cipherText = new byte[cipher.GetOutputSize(input.Length)];
            var outputLen = cipher.ProcessBytes(input, 0, input.Length, cipherText, 0);
            cipher.DoFinal(cipherText, outputLen);
            return cipherText;
        }

        private static byte[] DES_Decrypt(byte[] key, byte[] cipherText)
        {
            var engine = new DesEngine();
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine));
            cipher.Init(false, new KeyParameter(key));
            var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];
            var outputLen = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
            cipher.DoFinal(plainText, outputLen); 
            return plainText;
        }
    }
}

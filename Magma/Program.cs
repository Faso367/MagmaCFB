using System;
using System.Linq;
using System.Text;
using ExtensionMethods;

namespace Magma
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Введите открытый текст в 16-ричной СС: ");
            string hex_message = Console.ReadLine();

            //string hex_message = "fedcba9876543210";
            string default_key = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
            byte[] byte_key = default_key.ToByteArray();
            Console.WriteLine("Шифруемое hex-сообщение: " + hex_message);
            Console.WriteLine($"Ключ шифрования:\n{byte_key.ToHexString()}");

            string encryptMessage = Magma.Encrypt(hex_message, byte_key);
            Console.WriteLine($"Зашифрованное сообщение:\n{encryptMessage}");

            Console.WriteLine($"Расшифрованное сообщение:\n{Magma.Decrypt(encryptMessage, byte_key)}");

            // Должны получить  4ee901e5c2d8ca3d
        }
    }
}

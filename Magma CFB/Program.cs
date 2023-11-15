using System;
using System.Text;
using ExtensionMethods;

namespace MagmaCFB
{
    class Program
    {
        static void Main(string[] args)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            string key = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
            string IV = "1234567890abcdef234567890abcdef1";
            string openTextForCFB = "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41";

            byte[] byte_CFB_message = Convert.FromHexString(openTextForCFB);
            byte[] byte_key = key.ToByteArray();
            byte[] byte_IV = Convert.FromHexString(IV);

            Console.WriteLine($"Ключ шифрования:\n{byte_key.ToHexString()}");
            Console.WriteLine($"Синхропосылка:\n{byte_IV.ToHexString()}");

            byte[] encryptMessage = Magma.CFBEncrypt(byte_IV, byte_CFB_message, byte_key);
            Console.WriteLine($"Зашифрованное сообщение:\n{encryptMessage.NewToHexString()}");

        }
    }
}

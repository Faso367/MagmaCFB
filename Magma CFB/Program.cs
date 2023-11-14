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



            string hex_message = "fedcba9876543210";
            string default_key = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

            string IV = "1234567890abcdef234567890abcdef1";
            //const int registerLength = 128;
            const int registerLength = 16;


            //string hex_message_with_spaces = "fe dc ba 98 76 54 32 10";
            //hex_message_with_spaces = hex_message_with_spaces.ToUpper();
            //Console.WriteLine(hex_message_with_spaces);
            //string default_key_hex =
            //string default_key_hex = "00 "

            //default_key = "00" + default_key;

            string usual_message = "";

            //string hexValues = "48 65 6C 6C 6F 20 57 6F 72 6C 64 21";
            //string[] hexValuesSplit = hex_message_with_spaces.Split(' ');
            //foreach (string hex in hexValuesSplit)
            //{
            //    // Convert the number expressed in base-16 to an integer.
            //    int value = Convert.ToInt32(hex, 16);
            //    // Get the character corresponding to the integral value.
            //    string stringValue = Char.ConvertFromUtf32(value);
            //    char charValue = (char)value;
            //    usual_message += stringValue;
            //    Console.WriteLine("hexadecimal value = {0}, int value = {1}, char value = {2} or {3}",
            //                        hex, value, stringValue, charValue);
            //}
            //Console.WriteLine("Сообщение: " + usual_message);


            //Console.WriteLine(default_key);
            //Console.WriteLine(default_key.Length);

            //byte[] byte_key = Encoding.UTF8.GetBytes(default_key);

            string openTextForCFB = "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41";


            byte[] byte_CFB_message_old = openTextForCFB.ToByteArray();
            //byte[] byte_key = default_key.ToByteArray();
            //byte[] byte_IV = IV.ToByteArray();
            byte[] byte_CFB_message = Convert.FromHexString(openTextForCFB);

            //byte[] byte_key = Convert.FromHexString(default_key); БЫЛО
            byte[] byte_key = default_key.ToByteArray();

            byte[] byte_IV = Convert.FromHexString(IV);

            Console.WriteLine($"Ключ шифрования:\n{byte_key.ToHexString()}");
            Console.WriteLine($"Синхропосылка:\n{byte_IV.ToHexString()}");

            //string encryptMessage = Magma.MyEncrypt(hex_message, byte_key);

            //string encryptMessage = Magma.CFBEncrypt(byte_IV, hex_message, byte_key, registerLength);
            //string encryptMessage = Magma.CFBEncrypt(byte_IV, byte_CFB_message, byte_key, registerLength);
            string encryptMessage = Magma.CFBEncrypt(byte_IV, byte_CFB_message, byte_key);


            Console.WriteLine($"Зашифрованное сообщение:\n{encryptMessage}");

        }
    }
}

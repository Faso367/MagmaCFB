﻿using System;
using System.Linq;
using System.Numerics;
using System.Text;
using ExtensionMethods;

namespace Magma
{
    /// <summary>
    /// Реализация ГОСТ Р 34.12-2015
    /// </summary>
    static class Magma
    {
        // pi-подстановка
        private static readonly byte[][] pi = new byte[8][]
        {
            new byte[16] {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
            new byte[16] {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
            new byte[16] {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
            new byte[16] {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
            new byte[16] {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
            new byte[16] {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
            new byte[16] {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
            new byte[16] {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}
        };

        //public static string MyToHexString(this string input)
        //{
        //    char[] values = input.ToCharArray();
        //    string hex_string = "";

        //    byte[] arr;

        //    //string stroka = Convert.ToHexString(arr, 5, 6);

        //    foreach (char letter in values)
        //    {
        //        // Get the integral value of the character.
        //        int value = Convert.ToInt32(letter);
        //        //hex_string += ()value.ToString();
        //        // Convert the integer value to a hexadecimal value in string form.
        //        Console.WriteLine($"Hexadecimal value of {letter} is {value:X}");
        //        Console.WriteLine(hex_string);
        //    }
        //    return hex_string;
        //}

        /// <summary>
        /// Выполняет шифрование сообщения
        /// </summary>
        /// <param name="message">Сообщение</param>
        /// <param name="key">256-битный ключ</param>
        //public static string Encrypt(string message, byte[] key)
        //{
        //    string encryptMessage = "";
        //    // Тут разбивают на блоки по 8 символов (а не по 16), тк каждый char символ в hex формате
        //    // будет в 2 раза больше. Поэтому надо на вход этой функции подавать обычный открытый текст, а не 16ричный
        //    int blockCount = message.Length % 8 == 0 ? message.Length / 8 : message.Length / 8 + 1;
        //    for (int i = 0; i < blockCount; i++)
        //    {
        //        string part = message.PadRight(blockCount * 8).Substring(i * 8, 8).PadRight(8);
        //        Console.WriteLine($"Part: {part}");
        //        string tmp = part.MyToHexString();

        //        //string tmp = part.ToHexStringReverse();

        //        Console.WriteLine("Check: " + tmp);
        //        byte[] messageBytes = part.ToHexString().ToByteArray();
        //        byte[][] K = GetIterationKeys(key);
        //        byte[] encryptBytes = E(messageBytes, K);
        //        encryptMessage += encryptBytes.ToHexString();
        //    }
        //    return encryptMessage;
        //}
        //public static string MyEncrypt(string message, byte[] key)
        //{
        //    string encryptMessage = "";
        //    //int blockCount = message.Length % 8 == 0 ? message.Length / 8 : message.Length / 8 + 1;
        //    //for (int i = 0; i < 1; i++)
        //    //{
        //        //string part = message.PadRight(blockCount * 8).Substring(i * 8, 8).PadRight(8);
        //        //string tmp = part.ToHexString();
        //        //Console.WriteLine("Check: " + tmp);
        //        //string tmp = "fedcba9876543210";

        //        //byte[] messageBytes = part.ToHexString().ToByteArray();
        //        //byte[] messageBytes = tmp.ToByteArray();
        //        byte[] messageBytes = message.ToByteArray();
        //        byte[][] K = GetIterationKeys(key);
        //        byte[] encryptBytes = E(messageBytes, K);
        //        encryptMessage += encryptBytes.ToHexString();
        //    //}
        //    return encryptMessage;
        //}

        public static string Encrypt(string message, byte[] key)
        {
            string encryptMessage = "";

            byte[] messageBytes = message.ToByteArray();
            byte[][] K = GetIterationKeys(key);

            //Console.WriteLine("Итерационные ключи: \n");
            //foreach (var row in K)
            //  Console.WriteLine(Convert.ToHexStringReverse(row).ToLower());

            byte[] encryptBytes = E(messageBytes, K);

            encryptMessage += encryptBytes.ToHexStringReverse();
            return encryptMessage;
        }


        /// <summary>
        /// Выполняет выработку итерационных ключей
        /// </summary>
        /// <param name="key">256-битный ключ</param>
        /// <returns></returns>
        private static byte[][] GetIterationKeys(byte[] key)
        {
            byte[][] K = new byte[32][];
            for (int i = 0; i < 8; i++)
            {
                // Часть 1 
                K[i] = key.Skip(28 - 4 * i).Take(4).ToArray();
                // Часть 2
                K[i + 8] = K[i];
                // Часть 3
                K[i + 16] = K[i];
            }

            //K[0] = последние 4 бита ключа

            //Копирую 4 бита
            //K[8] = K[0];
            //K[16] = K[0];

            //K[1] = 4 бита влево
            //K[9] = K[1];
            //K[17] = K[2];

            // Последние 8 ключей в обратном порядке
            for (int i = 0; i < 8; i++)
                K[i + 24] = K[7 - i];

            //K[24] = K[7];
            //K[25] = K[6];

            return K;
        }
        //                                  ----- Алгоритм зашифрования Магма -----

        //                                                     1
        /// <summary>
        /// Делит входной блок сообщения на 2 части и запускает 32 раунда
        /// (то есть выполняет E-подстановку E = G*[K32]G[K31]...G[K1])
        /// </summary>
        /// <param name="message"> Блок открытого текста </param>
        /// <param name="K"> Зубчатый массив итерационных ключей </param>
        /// <returns> На выходе совокупность измененной левой и правой части </returns>
        private static byte[] E(byte[] message, byte[][] K)
        {
            // Числа а1 и а0 будем называть двоичными векторами
            byte[] a1 = message.Skip(4).ToArray(); // Первые 4 байта сообщения (изначально левая часть)
            byte[] a0 = message.Take(4).ToArray(); // Последние 4 байта (изначально правая часть)

            // Выполняем раундовые преобразования 32 раза
            for (int i = 0; i < 32; i++)
                G(K[i], ref a1, ref a0);

            return a1.Concat(a0).ToArray();
        }

        //                                                      2
        /// <summary>
        /// Выполняет 1 полный раунд (G-преобразование)
        /// </summary>
        /// <param name="K"> Итерационный ключ </param>
        /// <param name="a1"> 32-битная часть сообщения (левая или правая, зависит от раунда) </param>
        /// <param name="a0"> 32-битная часть сообщения (левая или правая, зависит от раунда) </param>
        private static void G(byte[] K, ref byte[] a1, ref byte[] a0)
        {
            // Меняю части местами
            byte[] part = a1;
            a1 = a0;
            // Преобразую одну часть
            a0 = XOR(SmallG(K, a0), part);
        }

        //                                                      3
        /// <summary>
        /// Выполняет g-преобразование
        /// </summary>
        /// <param name="K">Итерационный ключ</param>
        /// <param name="a">32-битная часть сообщения</param>
        /// 
        private static byte[] SmallG(byte[] K, byte[] a)
        {
            byte[] sum = AddMod32(K, a);

            // Разбиваем результат сложения на массив из 4-битовых векторов (удобно для замен)
            byte[] fourBitsArray = sum.ToFourBitsArray();

            // t-преобразование, выполняющее замену
            // Бит из вектора заменяется на бит из таблицы замены
            // (предыдущее значение бита выступает номером числа, на который он будет заменен)
            for (int i = 0; i < 8; i++)
                fourBitsArray[i] = pi[i][fourBitsArray[i]];

            byte[] normalBytes = fourBitsArray.ToByteArray();
            byte[] res = LeftShift11(normalBytes); // Сдвигаем байты на 11 влево
            return res;
        }

        //                                                        4
        /// <summary>
        /// Сложение в кольце 2^32 (значит по модулю 32)
        /// </summary>
        /// <param name="a">Первое число</param>
        /// <param name="b">Второе число</param>
        private static byte[] AddMod32(byte[] a, byte[] b)
        {
            byte[] tmp = (new BigInteger(a) + new BigInteger(b) % BigInteger.Pow(2, 32)).ToByteArray();

            // Если вдруг придется дополнять длину
            if (tmp.Length < 4)
                tmp = tmp.Concat(new byte[1]).ToArray();

            byte[] res = new byte[4];
            Array.Copy(tmp, 0, res, 0, 4);
            return res;
        }
        //                                                       5
        /// <summary>
        /// Выполняет циклический сдвиг последовательности на 11 бит влево
        /// </summary>
        /// <param name="arr"></param>
        /// <returns></returns>
        private static byte[] LeftShift11(byte[] arr)
        {
            string bitsString = "";
            for (int i = 0; i < 4; i++) // байты в двоичные строки
            {
                StringBuilder binary = new StringBuilder(Convert.ToString(arr[i], 2));
                binary.Insert(0, "0", 8 - binary.Length);
                bitsString = binary.ToString() + bitsString;
            }
            char[] bits = bitsString.ToCharArray();
            char[] tmp = new char[11];

            for (int i = 0; i < 11; i++)
                tmp[i] = bits[i];

            for (int i = 0; i < 21; i++)
                bits[i] = bits[i + 11];

            for (int i = 21; i < 32; i++)
                bits[i] = tmp[i - 21];

            byte[] res = new byte[4];
            for (int i = 0; i < 4; i++) // двоичные строки в байты
                res[4 - i - 1] = Convert.ToByte(new string(bits.Skip(i * 8).Take(8).ToArray()), 2);

            return res;
        }

        //                                                      6
        /// <summary>
        /// Выполняет xor двух массивов байт
        /// </summary>
        private static byte[] XOR(byte[] k, byte[] a)
        {
            byte[] result = new byte[4];
            for (int i = 0; i < 4; i++)
                result[i] = (byte)(k[i] ^ a[i]);

            return result;
        }

        //                                         ------ Алгоритм расшифрования Магма -----

        /// <summary>
        /// Выполняет расшифрование сообщения
        /// </summary>
        /// <param name="message"> строка в 16-ричной СС </param>
        /// <param name="key"> 256-битный ключ </param>
        public static string Decrypt(string message, byte[] key)
        {
            string decryptMessage = "";
            for (int i = 0; i < message.Length / 16; i++)
            {
                byte[] messageBytes = message.ToByteArray();
                byte[][] K = GetIterationKeys(key);
                byte[] decryptBytes = D(messageBytes, K);
                decryptMessage += decryptBytes.ToHexStringReverse();
            }
            return decryptMessage;
        }

        /// <summary>
        /// Выполняет D-подстановку D = G*[K1]G[K2]...G[K32] (Преобразование, обратное E)
        /// </summary>
        /// <param name="message">Зашифрованное сообщение</param>
        /// <param name="K">Последовательность итерационных ключей</param>
        private static byte[] D(byte[] message, byte[][] K)
        {
            byte[] a1 = message.Skip(4).ToArray();
            byte[] a0 = message.Take(4).ToArray();

            for (int i = 31; i >= 0; i--)
                // Используем итерационные ключи в обратном порядке
                G(K[i], ref a1, ref a0);
            return a1.Concat(a0).ToArray();
        }

    }
}

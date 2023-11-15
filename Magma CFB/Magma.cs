﻿using System.Numerics;
using System.Text;
using ExtensionMethods;

namespace MagmaCFB
{
    /// <summary>
    /// Реализация ГОСТ Р 34.13-2015
    /// </summary>
    /// 
    static class Magma
    {
        // Таблица замены (еще называют pi-подстановкой)
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

        private const int n = 8;
        private const int s = 8;
        private const int m = 2 * n;

        /// <summary>
        /// Метод реализует ГОСТ 34.13-2015, режим гаммирования
        /// с обратной связью по шифртексту (алгоритм Магма)
        /// </summary>
        /// <param name="IV">Вектор инициализации</param>
        /// <param name="message">Весь открытый текст</param>
        /// <param name="key">Ключ шифрования (мастер-ключ)</param>
        /// <returns>Итоговый шифртекст</returns>
        public static byte[] CFBEncrypt(byte[] IV, byte[] message, byte[] key)
        {
            // Количество блоков открытого текста
            int blocksCount = message.Length % 8 == 0 ? message.Length / 8 : message.Length / 8 + 1;

            byte[] gammaMSB = new byte[n];
            byte[] gammaLSB = new byte[m-s];
            // При первой итерации гамма = вектору инициализации
            byte[] R = IV;
            byte[] Ci = new byte[s];
            byte[] C = new byte[Ci.Length * blocksCount];

            for (int i = 1; i < blocksCount + 1; i++)
            {
                //1) Если это не первая итерация, то гамма = LSB || Сi
                if (i != 1)
                    R = gammaLSB.Concat(Ci).ToArray();  

                byte[] messageBlock = message[(n * (i - 1))..(n * i)];

                Console.WriteLine($"P{i}: {messageBlock.NewToHexString()}");

                // 2) LSB - берём последние m-s символов от гаммы
                R[(m - s)..R.Length].CopyTo(gammaLSB, 0);
                //Console.WriteLine($"GammaLSB: {gammaLSB.NewToHexString()}");

                // MSB - берем первые n символов от гаммы
                R[0..n].CopyTo(gammaMSB, 0);
                //Console.WriteLine($"GammaMSB:{gammaMSB.NewToHexString()}");

                Console.WriteLine($"Входной блок: {gammaMSB.NewToHexString()}");

                // Вызываем метод базового алгоритма Магма (ek)
                string encryptRes = Encrypt(gammaMSB.NewToHexString(), key);
                //byte[] encryptRes = Encrypt(gammaMSB, key);
                Console.WriteLine("Выходной блок: " + encryptRes);
                //Console.WriteLine("Выходной блок: " + encryptRes.NewToHexString());

                byte[] usechenniyRes = Convert.FromHexString(encryptRes);

                // 4) Усекаем выход функции Encrypt (Ts)
                if (encryptRes.Length % s != 0)
                    usechenniyRes = Convert.FromHexString(encryptRes[0..s]);

                //Console.WriteLine($"Усеченный результат шифрования: {usechenniyRes.NewToHexString()}");

                // 5) XOR усеченного результата и открытого текста (s XOR P1)
                for (int j = 0; j < usechenniyRes.Length; j++)
                    Ci[j] = (byte)(usechenniyRes[j] ^ messageBlock[j]);

                Console.WriteLine($"C{i}:" + $" {Ci.NewToHexString()}\n");

                Ci.CopyTo(C, Ci.Length * (i-1));
            }
            return C;
        }

        /// <summary>
        /// Реализует базовый алгоритм Магма из ГОСТ 34.12-2015
        /// </summary>
        /// <param name="message">открытый текст</param>
        /// <param name="key">ключ шифрования</param>
        /// <returns></returns>
        
        public static string Encrypt(string message, byte[] key)
        //public static byte[] Encrypt(byte[] message, byte[] key)
        {
            //byte[] encryptMessage = new byte[message.Length];
            string encryptMessage = "";

            byte[] messageBytes = message.ToByteArray();
            byte[][] K = GetIterationKeys(key);

            //Console.WriteLine("Итерационные ключи: \n");
            //foreach (var row in K)
              //  Console.WriteLine(Convert.ToHexString(row).ToLower());

            byte[] encryptBytes = E(messageBytes, K);
            //byte[] encryptBytes = TransE(message, K);

            encryptMessage += encryptBytes.ToHexString();
            //encryptBytes.CopyTo(encryptMessage, 0);
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
                K[i] = key.Skip(28 - 4 * i).Take(4).ToArray();
                K[i + 8] = K[i];
                K[i + 16] = K[i];
            }

            // Ключи в правильном порядке, но каждый итерационный ключ в перевернутом виде.

            //K[0] = последние 4 бита ключа

            //Копирую 4 бита
            //K[8] = K[0];
            //K[16] = K[0];

            //K[1] = 4 бита влево
            //K[9] = K[1];
            //K[17] = K[2];



            // Последние 8 ключей в обратном порядке
            for (int i = 0; i < 8; i++)
            {
                K[i + 24] = K[7 - i];
            }

            //K[24] = K[7];
            //K[25] = K[6];

            return K;
        }

        //                                   -----  Алгоритм зашифрования Магма -----


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
            a0 = XOR(TransSmallG(K, a0), part);
        }

        //                                                      3
        /// <summary>
        /// Выполняет g-преобразование
        /// </summary>
        /// <param name="K">Итерационный ключ</param>
        /// <param name="a">32-битная часть сообщения</param>
        /// 
        private static byte[] TransSmallG(byte[] K, byte[] a)
        {
            byte[] sum = AddMod32(K, a);

            // Разбиваем результат сложения на массив из 4-битовых векторов (удобно для замен)
            byte[] fourBitsArray = sum.ToFourBitsArray();

            // t-преобразование, выполняющее замену
            // Бит из вектора заменяется на бит из таблицы замены
            // (предыдущее значение бита выступает номером числа, на который он будет заменен)
            for (int i = 0; i < 8; i++)
                fourBitsArray[i] = pi[i][fourBitsArray[i]];

            byte[] normalBytes = fourBitsArray.ToByteArray(); // ПЕРЕВОРАЧИВАЕМ ОБРАТНО
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
            return (new BigInteger(a) + new BigInteger(b) % BigInteger.Pow(2, 32)).ToByteArray();

            // Если вдруг придется дополнять длину (по факту такого ни разу не было, поэтому закомментил)
            //byte[] tmp = (new BigInteger(a) + new BigInteger(b) % BigInteger.Pow(2, 32)).ToByteArray();
            //if (tmp.Length < 4)
            //{
            //    tmp = tmp.Concat(new byte[1]).ToArray();
            //}
            //byte[] res = new byte[4];
            //Array.Copy(tmp, 0, res, 0, 4);
            //return res;
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
            {
                tmp[i] = bits[i];
            }
            for (int i = 0; i < 21; i++)
            {
                bits[i] = bits[i + 11];
            }
            for (int i = 21; i < 32; i++)
            {
                bits[i] = tmp[i - 21];
            }

            byte[] res = new byte[4];
            for (int i = 0; i < 4; i++) // двоичные строки в байты
            {
                res[4 - i - 1] = Convert.ToByte(new string(bits.Skip(i * 8).Take(8).ToArray()), 2);
            }

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
    }
}

// Сложение двух чисел в кольце это то же самое, что и (a + b) % 2^степень кольца,
// то есть (10 + 5) % 12 = 3 (где 12 это степень кольца)
// В нашем случае сетпень кольца = 32.
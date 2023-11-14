using System;
using System.Linq;
using System.Text;

namespace ExtensionMethods
{
    /// <summary>
    /// Дополнительные методы для каста
    /// </summary>
    public static class ConvertExtensions
    {
        /// <summary>
        /// Выполняет преобразование строки в ее 16-ричный вид
        /// </summary>
        /// <param name="input">Входная строка</param>
        public static string ToHexString(this string input)
        {
            var sb = new StringBuilder();
            var bytes = Encoding.GetEncoding(1251).GetBytes(input);
            foreach (var i in bytes)
            {
                sb.Append(i.ToString("X2"));
            }
            return sb.ToString();
        }

        /// <summary>
        /// Выполняет преобразование 16-ричной строки в обычную
        /// </summary>
        /// <param name="input">16-ричная строка</param>
        public static string ToDecString(this string input)
        {
            var bytes = new byte[input.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(input.Substring(i * 2, 2), 16);
            }
            return Encoding.GetEncoding(1251).GetString(bytes);
        }

        /// <summary>
        /// Выполняется преобразование массива байт в hex строку
        /// </summary>
        /// <param name="input">Входная строка</param>
        public static string ToHexString(this byte[] input)
        {
            //ПОЧЕМУ РАБОТАЕТ ЗЕРКАЛЬНО (ТАК БЫЛО)
            return BitConverter.ToString(input.Reverse().ToArray()).Replace("-", "").ToLower();
            //return BitConverter.ToString(input.ToArray()).Replace("-", "").ToLower();
        }

        public static string NewToHexString(this byte[] input)
        {
            //ПОЧЕМУ РАБОТАЕТ ЗЕРКАЛЬНО (ТАК БЫЛО)
            //return BitConverter.ToString(input.Reverse().ToArray()).Replace("-", "").ToLower();
            return BitConverter.ToString(input.ToArray()).Replace("-", "").ToLower();
        }

        /// <summary>
        /// Выполняет преобразование hex строки в массив байт
        /// </summary>
        /// <param name="input">Входная строка</param>
        public static byte[] ToByteArray(this string input)
        {
            byte[] bytes = new byte[input.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(input.Substring((bytes.Length - i - 1) * 2, 2), 16);
            }
            return bytes;
        }

        /// <summary>
        /// Переводит массив байт в массив 4-битовых последовательностей
        /// </summary>
        /// <param name="arr">Массив байт</param>
        public static byte[] ToFourBitsArray(this byte[] arr)
        {
            byte[] res = new byte[8];
            for (int i = 0; i < 4; i++)
            {
                res[2 * i] = (byte)(arr[i] % 16);
                res[2 * i + 1] = (byte)(arr[i] / 16);
            }
            return res;
        }

        /// <summary>
        /// Переводит массив 4-битовых последовательностей в массив байт
        /// </summary>
        /// <param name="arr">Массив байт</param>
        public static byte[] ToByteArray(this byte[] arr)
        {
            byte[] res = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                res[i] = (byte)(arr[2 * i + 1] * 16 + arr[2 * i]);
            }
            return res;
        }
    }
}

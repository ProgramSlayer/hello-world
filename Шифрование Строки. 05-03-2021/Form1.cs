using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;

namespace Шифрование_Строки._05_03_2021
{
    public partial class EncryptDecrypt : Form
    {
        // Пароль, из которого будет извлечён хэш-код
        // для записи в m_key.
        private string m_password;

        // Вектор инициализации.
        private byte[] m_iv = new byte[16] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                                             0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

        // Объект для создания хэш-кода SHA256.
        private SHA256 m_sha256;

        // Ключ шифрования.
        private byte[] m_key;

        public EncryptDecrypt()
        {
            InitializeComponent();
            m_password = GeneratePassword();
            
            m_sha256 = SHA256Managed.Create();

            // Запись хэш-кода пароля m_password.
            m_key = m_sha256.ComputeHash(Encoding.ASCII.GetBytes(m_password));
        }

        private void EncryptDecrypt_Load(object sender, EventArgs e)
        {
            // Вывод пароля шифрования в текстовом поле.
            textBox4.Text = m_password;
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }
        // Событие - нажата кнопка "Зашифровать".
        private void EncryptButton_Click(object sender, EventArgs e)
        {
            textBox2.Text = TextEncryption(textBox1.Text);
        }
        // Событие - нажата кнопка расшифровать.
        private void DecryptButton_Click(object sender, EventArgs e)
        {
            textBox3.Text = TextDecryption(textBox2.Text);
        }
        /// <summary>
        /// Шифрует полученную строку по стандарту AES.
        /// </summary>
        /// <param name="plainText"> Текст, который требуется зашифровать.</param>
        /// <returns>cipherText - зашифрованный текст.</returns>
        private string TextEncryption(string plainText)
        {
            // Объект класса Aes для симметричного шифрования строки plainText.
            Aes aes = Aes.Create();

            // Задан режим функционирования симметричного алгоритма.
            aes.Mode = CipherMode.CBC;

            // Установка ключа и вектора инициализации для симметричного алгоритма.
            aes.Key = m_key;
            aes.IV = m_iv;

            // Объект класса MemoryStream для хранения зашифрованных байтов.
            MemoryStream memoryStream = new MemoryStream();

            // Симметричный шифратор, основанный на объекте класса Aes.
            ICryptoTransform aesEncryptor = aes.CreateEncryptor();

            // Объект класса CryptoStream для записи данных в memoryStream.
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesEncryptor, CryptoStreamMode.Write);

            // Массив байтов plainBytes содержит байты строки plainText.
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            // Шифрование байтов из plainBytes.
            cryptoStream.Write(plainBytes, 0, plainBytes.Length);

            // Завершение процесса шифрования.
            cryptoStream.FlushFinalBlock();

            // Содержит массив байтов, преобразованных из зашифрованных данных memoryStream.
            byte[] cipherBytes = memoryStream.ToArray();

            // Завершение потоков memoryStream и cryptoStream.
            memoryStream.Close();
            cryptoStream.Close();

            // Хранит строку, полученную из массива байтов cipherBytes.
            string cipherText = Convert.ToBase64String(cipherBytes, 0, cipherBytes.Length);

            // Возврат зашифрованной строки.
            return cipherText;
        }

        /// <summary>
        /// Расшифровывает полученную строку по стандарту AES.
        /// </summary>
        /// <param name="encryptedText"> Зашифрованная строка.</param>
        /// <returns>decryptedText - расшифрованная строка.</returns>
        private string TextDecryption(string encryptedText)
        {
            // Объект класса Aes для симметричной расшифровки.
            Aes aes = Aes.Create();

            // Режим функционирования симметричного алгоритма.
            aes.Mode = CipherMode.CBC;

            // Ключ и вектор инициализации симметричного алгоритма.
            aes.Key = m_key;
            aes.IV = m_iv;

            // Объект для хранения расшифрованных байтов.
            MemoryStream memoryStream = new MemoryStream();

            // Дешифратор на основе объекта aes.
            ICryptoTransform aesDecryptor = aes.CreateDecryptor();

            // Объект для записи данных в memoryStream.
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesDecryptor, CryptoStreamMode.Write);

            // Расшифрованная строка, пока что пуста.
            string decryptedText = String.Empty;
            
            // Содержит байты encryptedText.
            byte[] cipherBytes = Convert.FromBase64String(encryptedText);
            
            // Запись расшифрованных байтов в memoryStream из cipherBytes.
            cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);
            
            // Завершение процесса расшифровки.
            cryptoStream.FlushFinalBlock();
            
            // Содержит расшифрованные данные memoryStream, переведённые в массив байтов.
            byte[] resultBytes = memoryStream.ToArray();

            // Содержит расшифрованную строку, полученную из байтов resultBytes.
            decryptedText = Encoding.UTF8.GetString(resultBytes, 0, resultBytes.Length);
            //decryptedText = Encoding.ASCII.GetString(resultBytes, 0, resultBytes.Length);

            // Завершение потоков memoryStream и cryptoStream.
            memoryStream.Close();
            cryptoStream.Close();
            
            // Возврат расшифрованной строки.
            return decryptedText;
        }
        /// <summary>
        /// Генерирует пароль для шифрования.
        /// </summary>
        /// <returns>password - созданный пароль.</returns>
        private string GeneratePassword()
        {
            string password = String.Empty;
            int passwordLength = 200;
            string allowedLetters = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm";
            string allowedNumbers = "123456789";
            string allowedSymbols = "`!@#№$%^:&?*()_-+=<>,./'[]{}";
            string allowed = allowedLetters + allowedNumbers + allowedSymbols;
            Random gnr = new Random();
            for (int index = 0; index != passwordLength; ++index)
            {
                password += allowed[gnr.Next(allowed.Length)];
            }
            return password;
        }

        private void textBox4_TextChanged(object sender, EventArgs e)
        {

        }
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using Xamarin.Forms;
using Xamarin.Forms.Xaml;

namespace Encryption
{
	[XamlCompilation(XamlCompilationOptions.Compile)]
	public partial class EncodePage : ContentPage
	{
		public EncodePage()
		{
			InitializeComponent();
		}

		private void input_TextChanged(object sender, TextChangedEventArgs e)
		{
			try
			{
				//------------------PKey----------------//
				var rsa = new RSACryptoServiceProvider();
				_privateKey = rsa.ToXmlString(true);
				_publicKey = rsa.ToXmlString(false);
				//--------------------------------------//
				string text = input.Text;

				if (text != "")
				{
					Sha1.Text = Sha1Hash(text);
					Sha256.Text = Sha256Hash(text);
					Sha384.Text = Sha384Hash(text);
					Sha512.Text = Sha512Hash(text);
					Md5.Text = MD5Hash(text);
					Encry.Text = EncryptSecret(text, "Hatari");
					Decry.Text = DecryptSecret(Encry.Text, "Hatari");
					EncryP.Text = Encrypt_publicKey(text);
					DecryP.Text = Decrypt_privateKey(EncryP.Text);
					EasyE.Text = Eneasy(text, "Hatari", "MigPeerapong");
					EasyD.Text = Deeasy(EasyE.Text, "Hatari", "MigPeerapong");
				}
				else
				{
					Sha1.Text = null;
					Sha256.Text = null;
					Sha384.Text = null;
					Sha512.Text = null;
					Md5.Text = null;
					Encry.Text = null;
					Decry.Text = null;
					EncryP.Text = null;
					DecryP.Text = null;
					EasyE.Text = null;
					EasyD.Text = null;
				}

			}
			catch (Exception ex)
			{
				throw ex;
			}
		}

		//-------------------------------------------------------------------------------//
		/// <summary>
		/// Encryption Password (Use Key and Username encode Password) By Build New Key for encode to decode in Api.
		/// Use to Scrolling principle.
		/// </summary>
		/// <param name="plainText">Code Password</param>
		/// <param name="key">Keyword Encode and Decode top secret</param>
		/// <param name="userName">Username</param>
		/// <returns></returns>
		private string Eneasy(string plainText, string key, string userName)
		{
			try
			{
				//Keyword Change
				char[] alphabet = new char[26] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
				char[] input_array_key = key.ToCharArray();
				char[] input_array_user = userName.ToCharArray();
				int number = 0;
				string openKeyText = "Unsuccess";

				//Count text
				for (int i = key.Length - 1; i >= 0; i--)
				{
					number = number + Convert.ToInt32(input_array_key[i]);
					if (i == 0 && number % 2 == 1)
					{
						openKeyText = Convert.ToString(input_array_key[key.Length - 1]) + Convert.ToString(input_array_user[userName.Length - 1]);//Recheck Keyword key and user
					}
				}
				input_array_key[0] = alphabet[(key.Length) % alphabet.Length];
				string textPlainText = openKeyText + Convert.ToString(input_array_key[0]) + "$" + Convert.ToChar(number);

				//New Gen Encode
				char superKey = Convert.ToChar(DateTime.Now.DayOfYear - DateTime.Now.Second - DateTime.Now.Minute - DateTime.Now.Hour);//Keyword Control Main Plaintext
				char[] arrPlainText = (plainText + superKey).ToCharArray();
				char[] arrKey = key.ToCharArray();
				int[] arrText = new int[plainText.Length + 1];
				char[] arrex = new char[plainText.Length + 1];
				for (int i = plainText.Length; i >= 0; i--)
				{
					int keyA = 0;
					for (int j = 0; j < key.Length; j++)
					{
						keyA = keyA + Convert.ToInt32(arrKey[j]);
					}
					arrText[i] = Convert.ToInt32(arrPlainText[i]) + keyA + i;
					arrex[i] = Convert.ToChar(arrText[i]);
					textPlainText = textPlainText + arrex[i];
					int num = textPlainText.Length;
				}

				return textPlainText;
			}
			catch
			{
				return null;
			}
		}

		/// <summary>
		/// Decode one key not decode ciphertext
		/// </summary>
		/// <param name="ciphertext">ciphertext from xamarin</param>
		/// <param name="key">Keyword Encode and Decode top secret</param>
		/// <param name="userName">Username</param>
		/// <returns></returns>
		private string Deeasy(string ciphertext, string key, string userName)
		{
			char[] alphabet = new char[26] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
			string[] split = ciphertext.Split("$".ToCharArray());//split key
			char[] input_array_key_one = split[0].ToCharArray();
			char[] input_array_key_two = split[1].ToCharArray();
			char[] input_array_key_three = key.ToCharArray();
			char[] input_array_key_four = userName.ToCharArray();
			string password = ""; int number = 0;
			if (input_array_key_one[0] == input_array_key_three[key.Length - 1] && input_array_key_one[1] == input_array_key_four[userName.Length - 1])
			{

				if (alphabet[(key.Length) % alphabet.Length] == input_array_key_one[split[0].Length - 1])
				{
					for (int j = key.Length - 1; j >= 0; j--)
					{
						number = number + Convert.ToInt32(input_array_key_three[j]);
					}
					for (int i = 2; i < split[1].Length; i++)
					{
						if (number % 2 == 1 && Convert.ToChar(number) == input_array_key_two[0])
						{
							password = password + input_array_key_two[i];
						}
					}
				}
			}

			password = sha256_hash(password, userName);


			return password.Length + "/" + password;
		}

		/// <summary>
		/// Encode Sha256 [Modified version]
		/// </summary>
		/// <param name="value">ciphertext from Decrypt</param>
		/// <param name="user">Username</param>
		/// <returns></returns>
		public static String sha256_hash(string value, string user)
		{
			StringBuilder Sb = new StringBuilder();
			StringBuilder Hash = new StringBuilder();

			using (var hash = SHA256.Create())
			{
				Encoding enc = Encoding.UTF8;
				Byte[] result = hash.ComputeHash(enc.GetBytes(value));
				int count = user.Length;

				foreach (Byte b in result)
				{
					if (count % 2 == 0)
					{
						Sb.Append(b.ToString("x2"));
					}
					else
					{
						Sb.Append(b.ToString());
					}

					count++;
				}
				char[] input_array_key_hash = Sb.ToString().ToCharArray();
				count = 0;
				for (int i = 0; i < Sb.ToString().Length; i++)
				{
					Match outwordkey = Regex.Match(Convert.ToString(input_array_key_hash[i]), @"[0-9]{1}");
					if (outwordkey.Success)
					{
						count = count + Convert.ToInt32(input_array_key_hash[i]);
					}
					else
					{
						Hash.Append(input_array_key_hash[i]);
					}
				}
				Hash.Append(count);
			}
			return Hash.ToString();
		}
		//-------------------------------------------------------------------------------//

		//------------------PKey----------------//
		private static string _privateKey;
		private static string _publicKey;
		private static UnicodeEncoding _encoder = new UnicodeEncoding();
		//--------------------------------------//

		//------------------SKey----------------//
		private const int Keysize = 256;
		private const int DerivationIterations = 1000;
		//--------------------------------------//

		//--------------------------------------//
		public const int SALT_SIZE = 24; // size in bytes
		public const int HASH_SIZE = 24; // size in bytes
		public const int ITERATIONS = 100000; // number of pbkdf2 iterations

		public static byte[] CreateHash(string input)
		{
			// Generate a salt
			RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
			byte[] salt = new byte[SALT_SIZE];
			provider.GetBytes(salt);

			// Generate the hash
			Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(input, salt, ITERATIONS);
			return pbkdf2.GetBytes(HASH_SIZE);
		}
		//--------------------------------------//

		/// <summary>
		/// Decode to Password [Use Two Key or Public/Private Key]
		/// </summary>
		/// <param name="data">cipherText</param>
		/// <returns></returns>
		public static string Decrypt_privateKey(string data)
		{
			var rsa = new RSACryptoServiceProvider();
			var dataArray = data.Split(new char[] { ',' });
			byte[] dataByte = new byte[dataArray.Length];
			for (int i = 0; i < dataArray.Length; i++)
			{
				dataByte[i] = Convert.ToByte(dataArray[i]);
			}

			rsa.FromXmlString(_privateKey);
			var decryptedByte = rsa.Decrypt(dataByte, false);
			var hash = _encoder.GetString(decryptedByte);
			return hash;
		}

		/// <summary>
		/// Encode to Password [Use Two Key or Public/Private Key]
		/// </summary>
		/// <param name="data">Password</param>
		/// <returns></returns>
		public static string Encrypt_publicKey(string data)
		{
			var rsa = new RSACryptoServiceProvider();
			rsa.FromXmlString(_publicKey);
			var dataToEncrypt = _encoder.GetBytes(data);
			var encryptedByteArray = rsa.Encrypt(dataToEncrypt, false).ToArray();
			var length = encryptedByteArray.Count();
			var item = 0;
			var sb = new StringBuilder();
			foreach (var x in encryptedByteArray)
			{
				item++;
				sb.Append(x);

				if (item < length)
					sb.Append(",");
			}

			return sb.ToString();
		}

		/// <summary>
		/// Encode to Password [Use One Key or Secret Key]
		/// </summary>
		/// <param name="plainText">Password</param>
		/// <param name="passPhrase">Key Secret</param>
		/// <returns></returns>
		public static string EncryptSecret(string plainText, string passPhrase)
		{
			// Salt and IV is randomly generated each time, but is preprended to encrypted cipher text
			// so that the same Salt and IV values can be used when decrypting.  
			var saltStringBytes = Generate256BitsOfRandomEntropy();
			var ivStringBytes = Generate256BitsOfRandomEntropy();
			var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
			using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
			{
				var keyBytes = password.GetBytes(Keysize / 8);
				using (var symmetricKey = new RijndaelManaged())
				{
					symmetricKey.BlockSize = 256;
					symmetricKey.Mode = CipherMode.CBC;
					symmetricKey.Padding = PaddingMode.PKCS7;
					using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
					{
						using (var memoryStream = new MemoryStream())
						{
							using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
							{
								cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
								cryptoStream.FlushFinalBlock();
								// Create the final bytes as a concatenation of the random salt bytes, the random iv bytes and the cipher bytes.
								var cipherTextBytes = saltStringBytes;
								cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
								cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
								memoryStream.Close();
								cryptoStream.Close();
								return Convert.ToBase64String(cipherTextBytes);
							}
						}
					}
				}
			}
		}

		/// <summary>
		/// Decode to Password [Use One Key or Secret Key]
		/// </summary>
		/// <param name="cipherText">cipherText</param>
		/// <param name="passPhrase">Key Secret</param>
		/// <returns></returns>
		public static string DecryptSecret(string cipherText, string passPhrase)
		{
			// Get the complete stream of bytes that represent:
			// [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
			var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);
			// Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
			var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
			// Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
			var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
			// Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
			var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

			using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
			{
				var keyBytes = password.GetBytes(Keysize / 8);
				using (var symmetricKey = new RijndaelManaged())
				{
					symmetricKey.BlockSize = 256;
					symmetricKey.Mode = CipherMode.CBC;
					symmetricKey.Padding = PaddingMode.PKCS7;
					using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
					{
						using (var memoryStream = new MemoryStream(cipherTextBytes))
						{
							using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
							{
								var plainTextBytes = new byte[cipherTextBytes.Length];
								var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
								memoryStream.Close();
								cryptoStream.Close();
								var hash = Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
								return hash;
							}
						}
					}
				}
			}
		}

		/// <summary>
		/// Generate Sha256Hash Before Encode
		/// </summary>
		/// <returns></returns>
		private static byte[] Generate256BitsOfRandomEntropy()
		{
			var randomBytes = new byte[32]; // 32 Bytes will give us 256 bits.
			using (var rngCsp = new RNGCryptoServiceProvider())
			{
				// Fill the array with cryptographically secure random bytes.
				rngCsp.GetBytes(randomBytes);
			}
			return randomBytes;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="text">Password</param>
		/// <returns></returns>
		private string Sha256HashX2(string text)
		{
			SHA256 sha256Hash = SHA256.Create();
			byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(text));
			StringBuilder builder = new StringBuilder();
			for (int i = 0; i < bytes.Length; i++)
			{
				builder.Append(bytes[i].ToString("x2"));
			}
			return builder.ToString();
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="text">Password</param>
		/// <returns></returns>
		private string Sha1Hash(string text)
		{
			SHA1 sha1Hash = SHA1.Create();
			byte[] sourceBytes = Encoding.UTF8.GetBytes(text);
			byte[] hashBytes = sha1Hash.ComputeHash(sourceBytes);
			string hash = BitConverter.ToString(hashBytes).Replace("-", String.Empty);
			return hash.Length + "/" + hash;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="text">Password</param>
		/// <returns></returns>
		private string Sha256Hash(string text)
		{
			SHA256 sha256Hash = SHA256.Create();
			byte[] sourceBytes = Encoding.UTF8.GetBytes(text);
			byte[] hashBytes = sha256Hash.ComputeHash(sourceBytes);
			string hash = BitConverter.ToString(hashBytes).Replace("-", String.Empty);
			return hash.Length + "/" + hash;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="text">Password</param>
		/// <returns></returns>
		private string Sha384Hash(string text)
		{
			SHA384 sha384Hash = SHA384.Create();
			byte[] sourceBytes = Encoding.UTF8.GetBytes(text);
			byte[] hashBytes = sha384Hash.ComputeHash(sourceBytes);
			string hash = BitConverter.ToString(hashBytes).Replace("-", String.Empty);
			return hash.Length + "/" + hash;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="text">Password</param>
		/// <returns></returns>
		private string Sha512Hash(string text)
		{
			SHA512 sha512Hash = SHA512.Create();
			byte[] sourceBytes = Encoding.UTF8.GetBytes(text);
			byte[] hashBytes = sha512Hash.ComputeHash(sourceBytes);
			string hash = BitConverter.ToString(hashBytes).Replace("-", String.Empty);
			return hash.Length + "/" + hash;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="text">Password</param>
		/// <returns></returns>
		private string MD5Hash(string text)
		{
			MD5 md5Hash = MD5.Create();
			var sourceBytes = Encoding.UTF8.GetBytes(text);
			var hashBytes = md5Hash.ComputeHash(sourceBytes);
			var hash = BitConverter.ToString(hashBytes).Replace("-", string.Empty);
			return hash.Length + "/" + hash;
		}

		//---------------------------Test-Policy-Check-Word------------------------------//
		public bool Policy_Pass(string password, string username)
		{
			int passUser = Policy_Password_User(password, username);
			int passEqual = Policy_Password_Word(password, 0, 3);
			int pass1234 = Policy_Password_Word(password, 1, 3);
			int pass4321 = Policy_Password_Word(password, -1, 3);
			return true;
		}

		public int Policy_Password_Word(string passWord, int pointer, int matchWord)
		{
			char oneword = ' ';
			int count = 0;
			foreach (var item in passWord)
			{
				if (oneword + pointer == item)
				{
					oneword = item;
					count++;
				}
				else
				{
					oneword = item;
					count = 0;
				}
				if (count == matchWord)
				{
					return count;
				}
			}
			return count;
		}

		public int Policy_Password_Word_4321(string passWord)
		{
			char oneword = ' ';
			int count = 0;
			foreach (var item in passWord)
			{
				if (oneword - 1 == item)
				{
					oneword = item;
					count++;
				}
				else
				{
					oneword = item;
					count = 0;
				}
				if (count == 3)
				{
					return count;
				}
			}
			return count;
		}

		public int Policy_Password_Word_1234(string passWord)
		{
			char oneword = ' ';
			int count = 0;
			foreach (var item in passWord)
			{
				if (oneword + 1 == item)
				{
					oneword = item;
					count++;
				}
				else
				{
					oneword = item;
					count = 0;
				}
				if (count == 3)
				{
					return count;
				}
			}
			return count;
		}

		public int Policy_Password_Equal(string passWord)
		{
			char oneword = ' ';
			int count = 0;
			foreach (var item in passWord)
			{
				if (oneword == item)
				{
					count++;
				}
				else
				{
					oneword = item;
					count = 0;
				}
				if (count == 3)
				{
					return count;
				}
			}
			return count;
		}

		public int Policy_Password_User(string passWord, string userName)
		{
			char[] input_array_pass = passWord.ToCharArray();
			char[] input_array_user = userName.ToCharArray();
			int count = 0;
			for (int i = 0; i < 4; i++)
			{
				if (input_array_pass[i] == input_array_user[i])
				{
					count++;
				}
			}
			return count;
		}

		private void click_Clicked(object sender, EventArgs e)
		{
			//bool a = Policy_Pass("kpee1234321111", "kpeera");
			string v = "kpeerapong";
		}
		//-------------------------------------------------------------------------------//

	}
}
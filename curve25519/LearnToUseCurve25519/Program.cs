using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

using Whispersystems.Curve25519;

namespace LearnToUseCurve25519
{
	class MainClass
	{
		public static void Main (string [] args)
		{
			var curve = Curve25519.ConstructInstance(Curve25519.ImplementationType.Csharp);

			var keyA = curve.GenerateKeyPair();
			var keyB = curve.GenerateKeyPair();
		
			var sharedSymetricKeyA = curve.CalculateAgreement(keyA.PrivateKey, keyB.PublicKey);
			var sharedSymetricKeyB = curve.CalculateAgreement(keyB.PrivateKey, keyA.PublicKey);
			                                                  
			Console.WriteLine($"Party A symetric key: {Convert.ToBase64String(sharedSymetricKeyA)} ({sharedSymetricKeyA.Length * 8} bits)");
			Console.WriteLine($"Party B symetric key: {Convert.ToBase64String(sharedSymetricKeyB)} ({sharedSymetricKeyB.Length * 8} bits)");

			var random = new PCLSecureRandomProvider();

			// Create an Aes object
			// with the specified key and IV.
			using (var aesAlg = Aes.Create())
			{
				aesAlg.Key = sharedSymetricKeyA;

				aesAlg.IV = new byte[aesAlg.BlockSize / 8];
				random.NextBytes(aesAlg.IV);

				// Create an encrytor to perform the stream transform.
				var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

				// Create the streams used for encryption
				byte[] encrypted;
				using (var msEncrypt = new MemoryStream())
				{
					using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
					{
						using (var swEncrypt = new StreamWriter(csEncrypt))
						{
							swEncrypt.Write("To Encrypt");
							swEncrypt.Flush();
						}
					}

					encrypted = msEncrypt.ToArray();
				}

				Console.WriteLine($"Encrypted: {Convert.ToBase64String(encrypted)}");

				// Create a decrytor to perform the stream transform.
				var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

				using (var msDecrypt = new MemoryStream(encrypted))
				{
					using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
					{
						using (var swDecrypt = new StreamReader(csDecrypt))
						{
							var decrypted = swDecrypt.ReadToEnd();
							Console.WriteLine($"Decrypted: {decrypted}");
						}
					}
				}
			}

			// Experiment with signatures
			var message = new byte[4096];
			random.NextBytes(message);

			var corruptedMessage = message.ToArray();
			corruptedMessage[corruptedMessage.Length - 3]++;

			var signatureA = curve.CalculateSignature(keyA.PrivateKey, message);
			var verifiedA = curve.VerifySignature(keyA.PublicKey, message, signatureA);
			Console.WriteLine($"A's signature: {Convert.ToBase64String(signatureA)}, verified: {verifiedA}");

			var notVerifiedA = curve.VerifySignature(keyA.PublicKey, corruptedMessage, signatureA);
			Console.WriteLine($"Is a corrupted message verified? {notVerifiedA}");

			var signatureB = curve.CalculateSignature(keyB.PrivateKey, message);
			var verifiedB = curve.VerifySignature(keyB.PublicKey, message, signatureB);
			Console.WriteLine($"A's signature: {Convert.ToBase64String(signatureB)}, verified: {verifiedB}");
		}
	}
}

/** 
 * Copyright (C) 2015 langboost
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


using curve25519;
using System;
using System.Collections.Generic;
using System.Reflection;
/**
* Copyright (C) 2015 Open Whisper Systems
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
namespace org.whispersystems.curve25519
{
	/// <summary>
	/// A Curve25519 interface for generating keys, calculating agreements, creating signatures, and verifying signatures.
	/// Author: Moxie Marlinspike
	/// </summary>
    public class Curve25519
    {
		/// <summary>
		/// The type of provider
		/// </summary>
		public enum ImplementationType
		{
			/// <summary>
			/// Pure C#, PCL-compatible implementation
			/// </summary>
			Csharp,

			/// <summary>
			/// Pure C#, PCL-compatible, "donna"-optimized implementation
			/// </summary>
			Best
		}

		public static Curve25519 ConstructInstance(ImplementationType type)
        {
            return ConstructInstance(type, new BouncyCastleDotNETSha512Provider(), new PCLSecureRandomProvider());
        }

		public static Curve25519 ConstructInstance(ImplementationType type, csharp.ISha512 sha, SecureRandomProvider random)
        {
            switch (type)
            {
				case ImplementationType.Best:
                default:
					return new Curve25519(ConstructBestProvider(sha, random));

				case ImplementationType.Csharp:
					return new Curve25519(ConstructCSharpProvider(sha, random));
            }
        }

        private readonly ICurve25519Provider provider;

        private Curve25519(ICurve25519Provider provider)
        {
            this.provider = provider;
        }

		/// <summary>
		/// Curve25519 is backed by either a native 
		/// or managed provider.  By default it prefers the native provider, and falls back to the
		/// managed provider if the native library fails to load.
		/// </summary>
		/// <value><c>true</c> if is native; otherwise, <c>false</c>.</value>
		public bool IsNative
        {
			get
			{
            	return this.provider.IsNative;
			}
        }

        public byte [] GeneratePrivateKey()
        {
            return this.provider.GeneratePrivateKey();
        }

		public byte[] GeneratePrivateKey(byte[] random)
        {
			return this.provider.GeneratePrivateKey(random);
        }

        public byte [] GeneratePublicKey(byte [] privateKey)
        {
			return this.provider.GeneratePublicKey(privateKey);
        }

		/// <summary>
		/// Generates a Curve25519 keypair
		/// </summary>
		/// <returns>A randomly generated Curve25519 keypair</returns>
        public Curve25519KeyPair GenerateKeyPair()
        {
			byte[] privateKey = this.provider.GeneratePrivateKey();
			byte[] publicKey = this.provider.GeneratePublicKey(privateKey);

            return new Curve25519KeyPair(publicKey, privateKey);
        }

		/// <summary>
		/// Calculates an ECDH agreement
		/// </summary>
		/// <returns>A 32-byte shared secret</returns>
		/// <param name="privateKey">The Curve25519 (typically yours) private key</param>
		/// <param name="publicKey">The Curve25519 (typically remote party's) public key</param>
		public byte[] CalculateAgreement(byte[] privateKey, byte[] publicKey)
        {
			return this.provider.CalculateAgreement(privateKey, publicKey);
        }

		/// <summary>
		/// Calculates a Curve25519 signature
		/// </summary>
		/// <returns>A 64-byte signature</returns>
		/// <param name="privateKey">The private Curve25519 key to create the signature with</param>
		/// <param name="message">The message to sign</param>
		public byte[] CalculateSignature(byte[] privateKey, byte[] message)
        {
            byte[] random = provider.GetRandomBytes(64);
			return this.CalculateSignature(random, privateKey, message);
        }

		public byte[] CalculateSignature(byte[] random, byte[] privateKey, byte[] message)
        {
			return this.provider.CalculateSignature(random, privateKey, message);
        }

		/// <summary>
		/// Verify a Curve25519 signature
		/// </summary>
		/// <returns><c>true</c>, if signature was verified, <c>false</c> otherwise.</returns>
		/// <param name="publicKey">The Curve25519 public key the signature belongs to</param>
		/// <param name="message">The message that was signed</param>
		/// <param name="signature">The signature to verify</param>
		public bool VerifySignature(byte[] publicKey, byte[] message, byte[] signature)
        {
			return this.provider.VerifySignature(publicKey, message, signature);
        }

        private static ICurve25519Provider ConstructCSharpProvider(csharp.ISha512 sha, SecureRandomProvider random)
        {
			return new ManagedCurve25519Provider(sha, random);
        }

        private static ICurve25519Provider ConstructBestProvider(csharp.ISha512 sha, SecureRandomProvider random)
        {
			return new DonnaCSharpCurve25519Provider(sha, random);
        }

        /* TODO: Implement as appropriate to grow the flexibility of the library...
        private static Curve25519Provider constructNativeProvider(SecureRandomProvider random)
        {
            return constructClass("NativeCurve25519Provider", random);
        }
        */
    }
}

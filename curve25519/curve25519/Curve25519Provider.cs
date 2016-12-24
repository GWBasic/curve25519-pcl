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

using org.whispersystems.curve25519.csharp;
using System;

namespace org.whispersystems.curve25519
{
    /// <summary>
    /// Curve255919 in pure C#, without "donna" performance optimizations.
    /// </summary>
    public abstract class Curve25519Provider : ICurve25519Provider
    {
		public const int PRIVATE_KEY_LEN = 32;

        private ISha512 sha512provider;
        private SecureRandomProvider secureRandomProvider;

        public Curve25519Provider()
        {
            sha512provider = null;
            secureRandomProvider = null;
        }

        protected Curve25519Provider(ISha512 sha512provider,
                                             SecureRandomProvider secureRandomProvider)
        {
            this.sha512provider = sha512provider;
            this.secureRandomProvider = secureRandomProvider;
        }

		public virtual SecureRandomProvider RandomProvider
        {
			set { this.secureRandomProvider = value; }
        }

		public virtual ISha512 Sha512Provider
        {
			set { this.sha512provider = value; }
        }

		public abstract bool IsNative { get; }

		public virtual byte[] CalculateAgreement(byte[] ourPrivate, byte[] theirPublic)
        {
            byte[] agreement = new byte[32];
            Scalarmult.crypto_scalarmult(agreement, ourPrivate, theirPublic);

            return agreement;
        }

        public virtual byte[] GeneratePublicKey(byte[] privateKey)
        {
            byte[] publicKey = new byte[32];
            Curve_sigs.curve25519_keygen(publicKey, privateKey);

            return publicKey;
        }

		public virtual byte[] GeneratePrivateKey()
        {
            byte[] random = GetRandomBytes(Curve25519Provider.PRIVATE_KEY_LEN);
            return GeneratePrivateKey(random);
        }

		public virtual byte[] GeneratePrivateKey(byte[] random)
        {
            byte[] privateKey = new byte[32];

            Array.Copy(random, 0, privateKey, 0, 32);

            privateKey[0] &= 248;
            privateKey[31] &= 127;
            privateKey[31] |= 64;

            return privateKey;
        }

		public virtual byte[] CalculateSignature(byte[] random, byte[] privateKey, byte[] message)
        {
            byte[] result = new byte[64];

            if (Curve_sigs.curve25519_sign(sha512provider, result, privateKey, message, message.Length, random) != 0)
            {
                throw new ArgumentException("Message exceeds max length!");
            }

            return result;
        }

		public virtual bool VerifySignature(byte[] publicKey, byte[] message, byte[] signature)
        {
            return Curve_sigs.curve25519_verify(sha512provider, signature, publicKey, message, message.Length) == 0;
        }

		public virtual byte[] GetRandomBytes(int length)
        {
            byte[] result = new byte[length];
            secureRandomProvider.nextBytes(result);
            return result;
        }
    }
}

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

namespace org.whispersystems.curve25519
{
    /// <summary>
    /// Common for all implementations of providers Curve25519.
    /// </summary>
    public interface ICurve25519Provider
    {
        byte[] CalculateAgreement(byte[] ourPrivate, byte[] theirPublic);
        byte[] CalculateSignature(byte[] random, byte[] privateKey, byte[] message);
        byte[] GeneratePrivateKey();
        byte[] GeneratePrivateKey(byte[] random);
        byte[] GeneratePublicKey(byte[] privateKey);
        byte[] GetRandomBytes(int length);

		bool IsNative { get; }
        
		SecureRandomProvider RandomProvider { set; }
		ISha512 Sha512Provider { set; }
        bool VerifySignature(byte[] publicKey, byte[] message, byte[] signature);
    }
}

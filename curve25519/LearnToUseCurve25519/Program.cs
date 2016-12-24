using System;

using Whispersystems.Curve25519;

namespace LearnToUseCurve25519
{
	class MainClass
	{
		public static void Main (string [] args)
		{
			var curve = Curve25519.ConstructInstance(Curve25519.ImplementationType.Best);
			Console.WriteLine(curve);

			var keysA = curve.GenerateKeyPair();
			var keysB = curve.GenerateKeyPair();
		}
	}
}

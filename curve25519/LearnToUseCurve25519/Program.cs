using System;

using org.whispersystems.curve25519;

namespace LearnToUseCurve25519
{
	class MainClass
	{
		public static void Main (string [] args)
		{
			var curve = Curve25519.ConstructInstance(Curve25519.ImplementationType.Best);
			Console.WriteLine(curve);

			var keys = curve.GenerateKeyPair();
			GC.KeepAlive(keys);
		}
	}
}

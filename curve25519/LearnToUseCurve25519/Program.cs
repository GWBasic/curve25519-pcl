using System;

using org.whispersystems.curve25519;

namespace LearnToUseCurve25519
{
	class MainClass
	{
		public static void Main (string [] args)
		{
			var curve = Curve25519.getInstance(Curve25519.BEST);
			Console.WriteLine(curve);

			var keys = curve.generateKeyPair();
		}
	}
}

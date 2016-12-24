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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using org.whispersystems.curve25519;

namespace Curve25519ProfilingHarness
{
    class Program
    {
        private const int TEST_COUNT = 100;

        /// <summary>
        /// Plug code in here like a unit test to see it in the Diagnostic Tools window.
        /// </summary>
        static void Main(string[] args)
        {
            Console.WriteLine("BEGIN...");

			var stopWatch = Stopwatch.StartNew();

            var curve = Curve25519.ConstructInstance(Curve25519.ImplementationType.Best);

            for (int i = 0; i < TEST_COUNT; i++)
            {
				var privateKey = curve.GeneratePrivateKey();
                curve.GeneratePublicKey(privateKey);
            }

			stopWatch.Stop();

            Console.WriteLine("END...");
			Console.WriteLine($"Time elapsed (in ms): {stopWatch.ElapsedMilliseconds}");
            Console.ReadLine();
        }
    }
}

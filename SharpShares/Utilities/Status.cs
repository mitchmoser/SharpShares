using System;
using System.Diagnostics;
using System.Timers;

namespace SharpShares.Utilities
{
    class Status
    {
        public static int lastCount;
        public static int currentCount;
        public static int totalCount;
        private static Timer statusTimer;
        private static Stopwatch runTimer;

        internal static void StartOutputTimer()
        {
            PrintStatus();
            //Interval to display progress during enumeration in milliseconds (Default: 30000)
            int statusInterval = 10000;
            statusTimer = new Timer(statusInterval);
            runTimer = new Stopwatch();
            runTimer.Start();
            statusTimer.Elapsed += (sender, e) =>
            {
                PrintStatus();
                lastCount = currentCount;
            };
            statusTimer.AutoReset = true;
            statusTimer.Start();
        }

        internal static void PrintStatus()
        {
            Console.WriteLine(
                runTimer != null
                    ? $"Status: ({ (((float)currentCount / (float)totalCount) * 100).ToString("0.00") }%) {currentCount} computers finished (+{currentCount - lastCount} {(float)currentCount / (runTimer.ElapsedMilliseconds / 1000)})/s -- Using {Process.GetCurrentProcess().PrivateMemorySize64 / 1024 / 1024} MB RAM"
                    : $"Status: ({ (((float)currentCount / (float)totalCount) * 100).ToString("0.00") }%) {currentCount} computers finished (+{currentCount - lastCount}) -- Using {Process.GetCurrentProcess().PrivateMemorySize64 / 1024 / 1024} MB RAM");
        }
    }
}

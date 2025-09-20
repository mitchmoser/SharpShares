using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Text.RegularExpressions;

namespace SharpShares.Utilities
{
    // from https://stackoverflow.com/questions/4172677/c-enumerate-ip-addresses-in-a-range
    internal class IPRange
    {
        public IPRange(string ipRange)
        {
            if (ipRange == null)
                throw new ArgumentNullException();

            if (!TryParseCIDRNotation(ipRange) && !TryParseSimpleRange(ipRange))
                throw new ArgumentException();
        }

        public IEnumerable<IPAddress> GetAllIP()
        {
            int capacity = 1;
            for (int i = 0; i < 4; i++)
                capacity *= endIP[i] - beginIP[i] + 1;

            List<IPAddress> ips = new List<IPAddress>(capacity);
            for (int i0 = beginIP[0]; i0 <= endIP[0]; i0++)
            {
                for (int i1 = beginIP[1]; i1 <= endIP[1]; i1++)
                {
                    for (int i2 = beginIP[2]; i2 <= endIP[2]; i2++)
                    {
                        for (int i3 = beginIP[3]; i3 <= endIP[3]; i3++)
                        {
                            ips.Add(new IPAddress(new byte[] { (byte)i0, (byte)i1, (byte)i2, (byte)i3 }));
                        }
                    }
                }
            }

            return ips;
        }

        /// <summary>
        /// Parse IP-range string in CIDR notation.
        /// For example "12.15.0.0/16".
        /// </summary>
        /// <param name="ipRange"></param>
        /// <returns></returns>
        private bool TryParseCIDRNotation(string ipRange)
        {
            string[] x = ipRange.Split('/');

            if (x.Length != 2)
                return false;

            byte bits = byte.Parse(x[1]);
            uint ip = 0;
            String[] ipParts0 = x[0].Split('.');

            // if the user entered an incorrect CIRD range e.g. 172.18.100.50/24 which should be 172.18.100.0/24, fix it
            if (uint.Parse(ipParts0[3]) > 0 && bits != 32)
            {
                ipParts0[3] = "0";
            }

            for (int i = 0; i < 4; i++)
            {
                ip = ip << 8;
                ip += uint.Parse(ipParts0[i]);
            }

            byte shiftBits = (byte)(32 - bits);
            uint ip1 = (ip >> shiftBits) << shiftBits;

            if (ip1 != ip) // Check correct subnet address
                return false;

            uint ip2 = ip1 >> shiftBits;
            for (int k = 0; k < shiftBits; k++)
            {
                ip2 = (ip2 << 1) + 1;
            }

            beginIP = new byte[4];
            endIP = new byte[4];

            for (int i = 0; i < 4; i++)
            {
                beginIP[i] = (byte)((ip1 >> (3 - i) * 8) & 255);
                endIP[i] = (byte)((ip2 >> (3 - i) * 8) & 255);
            }

            return true;
        }


        /// <summary>
        /// Parse IP-range string "12.15-16.1-30.10-255"
        /// </summary>
        /// <param name="ipRange"></param>
        /// <returns></returns>
        private bool TryParseSimpleRange(string ipRange)
        {
            String[] ipParts = ipRange.Split('.');

            beginIP = new byte[4];
            endIP = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                string[] rangeParts = ipParts[i].Split('-');

                if (rangeParts.Length < 1 || rangeParts.Length > 2)
                    return false;

                beginIP[i] = byte.Parse(rangeParts[0]);
                endIP[i] = (rangeParts.Length == 1) ? beginIP[i] : byte.Parse(rangeParts[1]);
            }

            return true;
        }

        private byte[] beginIP;
        private byte[] endIP;
    }
}

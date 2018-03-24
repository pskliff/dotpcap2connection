using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace dotpcap2connection
{
    /// <summary>
    /// Extention Methods for Packet class
    /// </summary>
    public static class Extentions
    {
        /// <summary>
        /// Receives packet's datagram
        /// </summary>
        /// <returns>Tcp or Udp</returns>
        public static TransportDatagram GetDatagram(this Packet packet)
        {
            IpV4Datagram ip = packet.Ethernet.IpV4;
            if (ip.Protocol == IpV4Protocol.Tcp)
            {
                TcpDatagram tcp = ip.Tcp;
                return tcp;
            }
            else
            {
                UdpDatagram udp = ip.Udp;
                return udp;
            }

        }

        /// <summary>
        /// Gets full source and destination info of the packet
        /// </summary>
        /// <param name="packet">given packet</param>
        /// <param name="source">source address</param>
        /// <param name="destination">destination address</param>
        /// <param name="srcPort">source port</param>
        /// <param name="dstPort">destination port</param>
        public static void GetSrcDst(this Packet packet, out IpV4Address source, out IpV4Address destination, out ushort srcPort, out ushort dstPort)
        {
            IpV4Datagram ip = packet.Ethernet.IpV4;
            ushort sourcePort, destinationPort;

            switch (ip.Protocol)
            {
                case IpV4Protocol.Tcp:
                    {
                        TcpDatagram tcp = ip.Tcp;
                        sourcePort = tcp.SourcePort;
                        destinationPort = tcp.DestinationPort;
                        break;
                    }
                case IpV4Protocol.Udp:
                    {
                        UdpDatagram udp = ip.Udp;
                        sourcePort = udp.SourcePort;
                        destinationPort = udp.DestinationPort;
                        break;
                    }
                default:
                    {
                        sourcePort = 80;
                        destinationPort = 80;
                        break;
                    }
            }

            source = ip.Source;
            destination = ip.Destination;
            srcPort = sourcePort;
            dstPort = destinationPort;
        }

        /// <summary>
        /// Receives with a high probability a unique hashcode using source and destination info
        /// </summary>
        /// <param name="packet">given packet</param>
        /// <returns>Hash value</returns>
        public static int GetSDHash(this Packet packet)
        {
            IpV4Address src, dst;
            ushort sourcePort, destinationPort;

            packet.GetSrcDst(out src, out dst, out sourcePort, out destinationPort);

            unchecked
            {
                var hashCode = 13;
                hashCode = (src.GetHashCode() * 397) ^ sourcePort;
                hashCode += (dst.GetHashCode() * 397) ^ destinationPort;

                return hashCode;
            }
        }
    }
}

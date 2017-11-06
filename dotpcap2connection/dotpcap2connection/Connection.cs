using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace dotpcap2connection
{
    /// <summary>
    /// Represents network connection.
    /// Keeps all connection characteristics and 
    /// functionality to form them.
    /// </summary>
    public class Connection
    {
        #region Fields
        private DateTime startTime;
        private DateTime endTime;

        //originating host
        private IpV4Address source;

        //responding host
        private IpV4Address destination;

        //originating port
        private ushort sourcePort;

        //service
        private ushort destinationPort;

        private IpV4Protocol protocol;

        private List<Packet> packets;

        private List<Packet> directPackets;

        private List<Packet> backPackets;

        //timer to count 240 seconds timeout
        Timer timer;

        //amount of time, that timer should wait until closing the connection
        public static int timeWait = 24000;

        uint udpCount = 0;

        //flag related fields
        bool isTcp = false;
        bool isRST = false;
        bool isSynAck = false;
        bool isEstablished = false;
        bool isCloseWait = false;
        bool isClosed = false;
        int synCount = 0;
        int finCount = 0;

        //"true" if close attempt by originator
        //"false" if close attempt by responder
        bool closeInitiator = true;

        //"true" if RST by originator
        //"false" if RST by responder
        bool rstInitiator = true;

        //termination flag
        string flag = string.Empty;

        event EventHandler connectionClosedEvent;
        event EventHandler connectionEstablishedEvent;
        event EventHandler connectionCloseAttempEvent;


        #endregion

        #region Properties

        public List<Packet> DirectPackets
        {
            get { return directPackets.ToList(); }
        }

        public List<Packet> BackPackets
        {
            get { return backPackets.ToList(); }
        }

        public List<Packet> Packets
        {
            get { return packets; }
        }

        public ushort SourcePort
        {
            get { return sourcePort; }
        }

        public ushort DestinationPort
        {
            get { return destinationPort; }
        }

        public IpV4Address Source
        {
            get { return source; }
        }

        public IpV4Address Destination
        {
            get { return destination; }
        }

        public string StringSource
        {
            get { return $"{ source}:{ sourcePort}"; }
        }

        public string StringDestination
        {
            get { return $"{ destination}:{ destinationPort}"; }
        }

        public DateTime StartTime
        {
            get { return startTime; }
            set
            {
                if (value == null) throw new ArgumentNullException("Start time mustn't be null");
                startTime = value;
            }
        }

        public DateTime EndTime
        {
            get { return endTime; }
            set
            {
                if (value == null) throw new ArgumentNullException("End time mustn't be null");
                endTime = value;
            }
        }

        public IpV4Protocol Protocol
        {
            get
            {
                return protocol;
            }
        }

        public int SYNCount
        {
            get { return synCount; }
        }

        public int FINCount
        {
            get { return finCount; }
        }

        public bool IsRST
        {
            get { return isRST; }
        }

        public bool IsSYNACK
        {
            get { return isSynAck; }
        }

        public bool IsEstablished
        {
            get { return isEstablished; }
        }

        public bool IsCloseWait
        {
            get { return isCloseWait; }
        }

        public bool IsTCP
        {
            get { return isTcp; }
        }

        public bool CloseInitiator
        {
            get { return closeInitiator; }
        }

        public bool RSTInitiator
        {
            get { return rstInitiator; }
        }

        public bool IsClosed
        {
            get { return isClosed; }
        }

        public string Flag
        {
            get { return flag; }
        }
        #endregion

        public Connection(IpV4Address source, ushort sourcePort, IpV4Address destination, ushort destinationPort,
            Packet packet, EventHandler timerHandler, EventHandler establishedHandler, EventHandler closeWaitHandler)
        {
            this.source = source;
            this.sourcePort = sourcePort;
            this.destination = destination;
            this.destinationPort = destinationPort;

            startTime = DateTime.MinValue;
            endTime = startTime;

            connectionClosedEvent += timerHandler;
            connectionEstablishedEvent += establishedHandler;
            connectionCloseAttempEvent += closeWaitHandler;

            timer = new Timer(CallEventHandler, connectionClosedEvent, timeWait, -1);

            packets = new List<Packet>();
            directPackets = new List<Packet>();
            backPackets = new List<Packet>();
            packets.Add(packet);

            IpV4Datagram ip = packet.Ethernet.IpV4;
            protocol = ip.Protocol;

            TcpDatagram tcp = packet.GetDatagram() as TcpDatagram;
            isTcp = packet.GetDatagram() is TcpDatagram;

            if (tcp != null)
            {
                ++synCount;
                directPackets.Add(packet);
            }
            else
            {
                directPackets.Add(packet);
                isEstablished = true;
            }

        }

        #region Methods

        /// <summary>
        /// adds packet to list
        /// </summary>
        /// <param name="packet"></param>
        public void AddPacket(Packet packet)
        {
            TcpDatagram tcp = packet.GetDatagram() as TcpDatagram;

            packets.Add(packet);

            if (isTcp)
            {
                if (!isDirect(packet) && tcp.IsSynchronize && !isEstablished)
                {
                    ++synCount;
                    isSynAck = tcp.IsAcknowledgment;
                    backPackets.Add(packet);
                    if (synCount == 2)
                    {
                        isEstablished = true;
                        connectionEstablishedEvent(this, new EventArgs());
                        timer.Change(timeWait, -1);
                    }
                }
                else
                if (tcp.IsReset)
                {
                    isRST = true;
                    if (isDirect(packet))
                    {
                        directPackets.Add(packet);
                        rstInitiator = true;
                    }
                    else
                    {
                        backPackets.Add(packet);
                        rstInitiator = false;
                    }
                    flag = GetFlag();
                    timer.Dispose();
                    connectionClosedEvent(this, new EventArgs());

                }
                else
                if (isDirect(packet) && tcp.IsSynchronize && packets.Count == 2)
                {
                    packets[0] = packet;
                    packets.RemoveAt(1);
                    directPackets[0] = packet;
                    timer.Change(timeWait, -1);
                }
                else
                if (tcp.IsFin)
                {
                    ++finCount;
                    if (isDirect(packet)) directPackets.Add(packet);
                    else backPackets.Add(packet);
                    if (finCount == 2)
                    {
                        timer.Dispose();
                        isClosed = true;
                        flag = GetFlag();
                        connectionClosedEvent(this, new EventArgs());
                    }

                    else
                        if (finCount == 1)
                    {
                        isCloseWait = true;
                        closeInitiator = isDirect(packet);
                        connectionCloseAttempEvent(this, new EventArgs());
                        timer.Change(timeWait, -1);
                    }
                }
                else
                if (tcp.IsAcknowledgment)
                {
                    if (isDirect(packet)) directPackets.Add(packet);
                    else backPackets.Add(packet);
                    timer.Change(timeWait, -1);
                }
            }
            else
            {
                if (isDirect(packet)) directPackets.Add(packet);
                else backPackets.Add(packet);
                timer.Change(timeWait, -1);
            }

        }

        /// <summary>
        /// checks if packet was sent from source to destination
        /// </summary>
        /// <param name="packet">packet to check</param>
        /// <returns></returns>
        private bool isDirect(Packet packet)
        {

            IpV4Address src, dst;
            ushort srcPort, dstPort;

            packet.GetSrcDst(out src, out dst, out srcPort, out dstPort);

            return this.source == src; ;
        }

        /// <summary>
        /// Timer Callback Method
        /// </summary>
        /// <param name="state">EventHandler to execute</param>
        void CallEventHandler(object state)
        {
            EventHandler finished = state as EventHandler;
            if (finished != null)
            {

                flag = GetFlag();
                finished(this, new EventArgs());
            }
            timer.Dispose();
        }

        /// <summary>
        /// gets FLAG feature (Basic)
        /// </summary>
        /// <param name="con">connection to work with</param>
        /// <returns>flag</returns>
        private string GetFlag()
        {
            if (IsTCP)
            {
                if (!IsEstablished && !IsCloseWait && !IsRST) return "S0";
                else if (IsEstablished && !IsCloseWait && !IsRST) return "S1";
                else if (IsEstablished && !IsRST && IsCloseWait && !IsClosed && CloseInitiator) return "S2";
                else if (IsEstablished && !IsRST && IsCloseWait && !IsClosed && !CloseInitiator) return "S3";
                else if (!IsEstablished && IsRST && !RSTInitiator) return "REJ";
                else if (IsEstablished && IsRST && RSTInitiator) return "RSTO";
                else if (IsEstablished && IsRST && !RSTInitiator) return "RSTR";
                else if (!IsEstablished && IsRST && RSTInitiator) return "RSTOS0";
                else return "SF";
            }
            else return "SF";
        }

        /// <summary>
        /// Receives with a high probability a unique hashcode using source and destination info
        /// </summary>
        /// <returns>Hash value</returns>
        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = 13;
                hashCode = (source.GetHashCode() * 397) ^ sourcePort;
                hashCode += (destination.GetHashCode() * 397) ^ destinationPort;
                return hashCode;
            }

        }

        public override bool Equals(object obj)
        {
            Connection con = (obj as Connection);

            return con != null ? (DateTime.Equals(con.startTime, this.startTime) && DateTime.Equals(con.endTime, this.endTime) &&
                con.GetHashCode() == this.GetHashCode()) : false;
        }
        public override string ToString()
        {
            return string.Format($"\n\r[ Connection: \n\rStart:{startTime.ToString("yyyy-MM-dd hh:mm:ss.fff")}, End: {endTime.ToString("yyyy-MM-dd hh:mm:ss.fff")}" +
                $"\n\rSource: {source}:{sourcePort}, Destination: {destination}:{destinationPort}, \n\rPacketsNum: {packets.Count}," +
                $" DirPack:{directPackets.Count}, BackPack: {backPackets.Count} ]\n\r\n\r");
        }

        public string GetFlagsToString()
        {
            return string.Format($"\n\r{this.GetHashCode()}: \n\r[ isTCP = {isTcp}, SynCount = {synCount}, FinCount = {finCount}, " +
                $"isEST = {isEstablished}, \n\risSA = {isSynAck}, isClWait = {isCloseWait}, isRST = {isRST} ]");
        }

        #endregion
    }
}

using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace dotpcap2connection
{
    /// <summary>
    /// Distributes packets into connections and closes connections when they end
    /// </summary>
    public class Distributor
    {
        #region Fields

        //List of ended Connections
        ConcurrentQueue<Connection> FinalConnections;

        //unclosed connections with hash identificator
        Dictionary<int, Connection> ActiveConnections;

        //Connections waiting for establishment(with one SYN packet)
        Dictionary<int, Connection> EstWaitConnections;

        //Connections waiting to be closed(With 1 FIN packet or 2 FIN packets and timer)
        Dictionary<int, Connection> CloseWaitConnections;

        //Shows if ActiveConnections Dict has no items
        bool isEmpty;

        int conCount = 100;

        // Retrieve the device list from the local machine
        static IList<LivePacketDevice> allDevices;

        CancellationToken token;

        event EventHandler newConnectionEvent;

        #endregion

        public Distributor(ConcurrentQueue<Connection> finalConnections, EventHandler newConnectionHandler)
        {
            FinalConnections = finalConnections;
            ActiveConnections = new Dictionary<int, Connection>();
            EstWaitConnections = new Dictionary<int, Connection>();
            CloseWaitConnections = new Dictionary<int, Connection>();
            isEmpty = ActiveConnections.Count == 0;
            newConnectionEvent += newConnectionHandler;
            newConnectionEvent += (x, y) =>
            {
                Task.Run(() => { newConnectionHandler(x, y); });
            };

        }

        #region Methods

        /// <summary>
        /// Gets device list on local machine
        /// </summary>
        /// <returns>names and descriptions of every device</returns>
        public static string GetDevices()
        {
            string st = string.Empty;

            allDevices = LivePacketDevice.AllLocalMachine;

            if (allDevices.Count == 0)
            {
                return "No interfaces found! Make sure WinPcap is installed.";
            }

            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                st += (i + 1) + ". " + device.Name + "\n\r";
                if (device.Description != null)
                    st += " (" + device.Description + ")" + "\n\r";
                else
                    st += " (No description available)" + "\n\r";
            }

            return st;
        }


        /// <summary>
        /// chooseы network adapter based on parameter
        /// </summary>
        /// <returns>chosen adapter</returns>
        private PacketDevice ChooseDevice(string deviceIndexString)
        {

            int deviceIndex = 0;

            if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                deviceIndex < 1 || deviceIndex > allDevices.Count)
            {
                if (allDevices.Count > 0)
                    deviceIndex = 1;
                else throw new ArgumentNullException("No devices found, so it can't be chosen");
            }

            Connection.timeWait = 24000;

            // Take the selected adapter
            return allDevices[deviceIndex - 1];
        }



        /// <summary>
        /// reads traffic from .pcap file
        /// </summary>
        /// <param name="path">path to file</param>
        /// <returns></returns>
        private PacketDevice GetOfflineDevice(string path)
        {
            // Check parameter 
            if (path == null) throw new ArgumentNullException("Path to .pcap file is empty");

            Connection.timeWait = 4000;

            // Create the offline device
            return new OfflinePacketDevice(path);

        }



        /// <summary>
        /// Creates new Task to read packets
        /// </summary>
        /// <param name="readFromFile">show if it is needed to read from file</param>
        /// <param name="path">path to file (null if readFromFile is false)</param>
        public async Task ReadPacketsAsync(bool readFromFile, string path, CancellationToken cancelTok)
        {
            token = cancelTok;
            if (!readFromFile && allDevices == null) GetDevices();
            PacketDevice selectedDevice;



            try
            {
                selectedDevice = readFromFile ? GetOfflineDevice(path) : ChooseDevice(path);

            }
            catch (ArgumentNullException)
            {
                throw;
            }


            try
            {
                await Task.Run(() => ReadPackets(selectedDevice));
            }
            catch (InvalidOperationException ex)
            {
                throw new InvalidOperationException("Can't read .pcap file: \n\r[ " + ex.Message + " ]\n\r");
            }
            catch (FormatException)
            {
                throw;
            }
            catch (Exception ex)
            {

                Debug.WriteLine("In ReadPacksAsync: " + ex.Message);
            }


        }



        /// <summary>
        /// Captures packets via the selected device
        /// </summary>
        void ReadPackets(PacketDevice selectedDevice)
        {

            // Open the device
            using (PacketCommunicator communicator =
                selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                            // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1000))                                  // read timeout
            {
                // Check the link layer. We support only Ethernet for simplicity.
                if (communicator.DataLink.Kind != DataLinkKind.Ethernet)
                {
                    throw new FormatException("This program works only on Ethernet networks.");
                }

                // Compile the filter
                using (BerkeleyPacketFilter filter = communicator.CreateFilter("ip and (tcp or udp)"))
                {
                    // Set the filter
                    communicator.SetFilter(filter);
                }

                // start the capture
                try
                {
                    communicator.ReceivePackets(0, PacketHandler);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("Communicator: " + ex.Message);
                    return;
                }


            }
        }



        /// <summary>
        /// Callback function invoked by libpcap for every incoming packet
        /// </summary>
        /// <param name="packet">captured packet</param>
        private void PacketHandler(Packet packet)
        {
            if (token.IsCancellationRequested)
            {
                Debug.WriteLine("PackHandle CANCELED");
                return;
            }

            int hash = packet.GetSDHash();
            IpV4Address src, dst;
            ushort srcPort, dstPort;

            packet.GetSrcDst(out src, out dst, out srcPort, out dstPort);

            if (CloseWaitConnections.ContainsKey(hash))
                CloseWaitConnections[hash].AddPacket(packet);
            else
            if (ActiveConnections.ContainsKey(hash))
                ActiveConnections[hash].AddPacket(packet);
            else
            if (EstWaitConnections.ContainsKey(hash))
                EstWaitConnections[hash].AddPacket(packet);
            else
            {
                TcpDatagram tcp = packet.GetDatagram() as TcpDatagram;

                if (tcp != null)
                {
                    if (tcp.IsSynchronize)
                    {
                        EstWaitConnections.Add(hash, new Connection(src, srcPort, dst, dstPort, packet,
                        ConnectionClosedHandler, EstablishedHandler, CloseWaitHandler));
                    }
                }
                else
                    ActiveConnections.Add(hash, new Connection(src, srcPort, dst, dstPort, packet,
                   ConnectionClosedHandler, EstablishedHandler, CloseWaitHandler));
            }

        }


        /// <summary>
        /// Callback function invoked when connection closes(connectionClosedEvent)
        /// </summary>
        /// <param name="sender">Connection which invoked function</param>
        /// <param name="e">Clean EventArgs</param>
        public void ConnectionClosedHandler(object sender, EventArgs e)
        {
            if (sender is Connection)
            {
                Connection con = (Connection)sender;


                int hashcode = con.GetHashCode();

                if (con.IsEstablished && !con.IsCloseWait)
                {
                    try
                    {
                        var timeQuery = from p in ActiveConnections[hashcode].Packets orderby p.Timestamp select p.Timestamp;

                        //assign start and finish times of the connection
                        ActiveConnections[hashcode].StartTime = timeQuery.First();
                        ActiveConnections[hashcode].EndTime = timeQuery.Last();

                        //move connection to finished
                        FinalConnections.Enqueue(ActiveConnections[hashcode]);
                        ActiveConnections.Remove(hashcode);
                        if (FinalConnections.Count > conCount)
                            newConnectionEvent(this, new EventArgs());
                    }
                    catch (Exception ex)
                    {

                        Debug.WriteLine("ConnectionClosedHandler(Active part): " + ex.Message);
                    }

                }
                else
                if (con.IsCloseWait)
                {
                    try
                    {
                        var timeQuery = from p in CloseWaitConnections[hashcode].Packets orderby p.Timestamp select p.Timestamp;

                        CloseWaitConnections[hashcode].StartTime = timeQuery.First();
                        CloseWaitConnections[hashcode].EndTime = timeQuery.Last();

                        //move connection to finished
                        FinalConnections.Enqueue(CloseWaitConnections[hashcode]);
                        CloseWaitConnections.Remove(hashcode);
                        if (FinalConnections.Count > conCount)
                            newConnectionEvent(this, new EventArgs());
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine("ConnectionClosedHandler(ClWait part): " + ex.Message);
                    }

                }
                else
                {
                    try
                    {
                        var timeQuery = from p in EstWaitConnections[hashcode].Packets orderby p.Timestamp select p.Timestamp;

                        EstWaitConnections[hashcode].StartTime = timeQuery.First();
                        EstWaitConnections[hashcode].EndTime = timeQuery.Last();

                        //move connection to finished
                        FinalConnections.Enqueue(EstWaitConnections[hashcode]);
                        EstWaitConnections.Remove(hashcode);
                        if (FinalConnections.Count > conCount)
                            newConnectionEvent(this, new EventArgs());
                    }
                    catch (Exception ex)
                    {

                        Debug.WriteLine("ConnectionClosedHandler(EstWait part): " + ex.Message);
                    }

                }

            }
        }


        /// <summary>
        /// Callback function invoked when connection is established(connectionEstablishedEvent)
        /// </summary>
        /// <param name="sender">Connection which invoked function</param>
        /// <param name="e">Clean EventArgs</param>
        public void EstablishedHandler(object sender, EventArgs e)
        {
            if (sender is Connection)
            {
                Connection con = (Connection)sender;
                int hashcode = con.GetHashCode();
                try
                {
                    ActiveConnections.Add(hashcode, EstWaitConnections[hashcode]);
                    EstWaitConnections.Remove(hashcode);
                }
                catch (Exception ex)
                {

                    Debug.WriteLine("EstHandler: " + ex.Message);
                }



            }
        }


        /// <summary>
        /// Callback function invoked when connection attempted to close(connectionCloseAttempEvent)
        /// </summary>
        /// <param name="sender">Connection which invoked function</param>
        /// <param name="e">Clean EventArgs</param>
        public void CloseWaitHandler(object sender, EventArgs e)
        {
            if (sender is Connection)
            {
                Connection con = (Connection)sender;
                int hashcode = con.GetHashCode();
                try
                {
                    if (con.IsEstablished)
                    {
                        CloseWaitConnections.Add(hashcode, ActiveConnections[hashcode]);
                        ActiveConnections.Remove(hashcode);
                    }
                    else
                    {
                        CloseWaitConnections.Add(hashcode, EstWaitConnections[hashcode]);
                        EstWaitConnections.Remove(hashcode);
                    }
                }
                catch (Exception ex)
                {

                    Debug.WriteLine("CloseWaitHandler: " + ex.Message);
                }



            }
        }

        #endregion
    }
}

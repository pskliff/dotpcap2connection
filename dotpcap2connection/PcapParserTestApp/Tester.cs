using dotpcap2connection;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PcapParserTestApp
{
    static class Tester
    {
        static Distributor dt = new Distributor(FinalConnections, (x,y) => { });
        static ConcurrentQueue<Connection> FinalConnections = new ConcurrentQueue<Connection>();
        static CancellationTokenSource cancelTokenSource = new CancellationTokenSource();
        static CancellationToken token = cancelTokenSource.Token;

        public static async void TestReadPacksAsync()
        {

            Console.WriteLine("TstReadPackAs " + Thread.CurrentThread.ManagedThreadId);

            await dt.ReadPacketsAsync(true, @"..\..\darpa98outside.pcap", token);
            Console.WriteLine("axaxa");

        }

        public static void Stop()
        {
            cancelTokenSource.Cancel();
        }

        public static void TestReadPacks()
        {

            Console.WriteLine("TstReadPack " + Thread.CurrentThread.ManagedThreadId);
            // dt.ReadPackets(true, @"..\..\..\smallFlows.pcap");

            TestReadPacksAsync();
            Console.WriteLine("axaxaTRP");
            Connection con;
            for (int i = 0; i < 20; i++)
            {
               // Thread.Sleep(10000);
                Console.WriteLine("TEsrReadPackCircle");
                if (FinalConnections.Count != 0)
                {
                    for (int j = 0; j < FinalConnections.Count; j+=10)
                    {
                        if (FinalConnections.TryDequeue(out con))
                        {
                            Console.WriteLine(con);
                        }
                        else
                            Console.WriteLine("CANNOT DEQUEUE");
                    }

                }

            }
        }
    }
}

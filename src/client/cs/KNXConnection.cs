/*
    EIBD client library
    Copyright (C) 2005-2011 Martin Koegler <mkoegler@auto.tuwien.ac.at>
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    In addition to the permissions in the GNU General Public License, 
    you may link the compiled version of this file into combinations
    with other programs, and distribute those combinations without any 
    restriction coming from the use of this file. (The General Public 
    License restrictions do apply in other respects; for example, they 
    cover modification of the file, and distribution when not linked into 
    a combine executable.)
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

namespace KNX
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading.Tasks;

    public struct KNXAddr
    {
        private ushort knxAddr;
        public ushort Value { get { return knxAddr; } }

        public KNXAddr(ushort val = 0)
        {
            knxAddr = val;
        }

        public override string ToString()
        {
            return $"{(Value >> 12) & 0xf}.{(Value >> 8) & 0xf}.{(Value & 0xff)}";
        }
    }

    public struct GroupAddr
    {
        private ushort gaddr;
        public ushort Value { get { return gaddr; } }
        public static ushort Make(ushort a, ushort b)
        {
            return (ushort)(((a & 0x1f) << 11) + (b & 0x7ff));
        }
        public static ushort Make(ushort a, ushort b, ushort c)
        {
            return (ushort)(((a & 0x1f) << 11) + ((b & 0x7) << 8) + (c & 0xff));
        }

        public static ushort Make(string addr)
        {
            var split = addr.Split('/');

            if (split.Length == 2)
                return Make(Convert.ToUInt16(split[0]), Convert.ToUInt16(split[1]));

            if (split.Length == 3)
                return Make(Convert.ToUInt16(split[0]), Convert.ToUInt16(split[1]), Convert.ToUInt16(split[2]));

            throw new FormatException("Expected format: ##/## or ##/##/##");
        }
        public GroupAddr(ushort a = 0)
        {
            gaddr = a;
        }
        public GroupAddr(ushort a, ushort b)
        {
            gaddr = Make(a, b);
        }
        public GroupAddr(ushort a, ushort b, ushort c)
        {
            gaddr = Make(a, b, c);
        }
        public GroupAddr(string addr)
        {
            gaddr = Make(addr);
        }

        public override string ToString()
        {
            return $"{(gaddr >> 11) & 0x1f}/{(gaddr >> 8) & 0x07}/{(gaddr) & 0xff}";
        }
    }

    public class KNXConnection
    {

        private TcpClient tcpClient;
        private NetworkStream tcpStream;

        public KNXConnection(String host) : this(host, 6720)
        {}

        public KNXConnection(String host, int port) : this(new IPEndPoint(Dns.GetHostEntry(host).AddressList[0], port))
        {}

        public KNXConnection(IPEndPoint endpoint) {
            tcpClient = new TcpClient();
            tcpClient.Connect(endpoint);
            tcpClient.Client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, 1);
            tcpStream = tcpClient.GetStream();
        }

        public IPEndPoint RemoteEndPoint {  get { return tcpClient.Client.RemoteEndPoint as IPEndPoint; } }

        protected async Task SendRequestAsync(byte[] data)
        {
            if (data.Length > 0xffff || data.Length < 2)
                throw new ArgumentException("invalid SendRequest length");

            byte[] len = new byte[2];
            len[0] = (byte)((data.Length >> 8) & 0xff);
            len[1] = (byte)((data.Length) & 0xff);

            await tcpStream.WriteAsync(len, 0, len.Length);
            await tcpStream.WriteAsync(data, 0, data.Length);
        }

        protected void SendRequest(byte[] data)
        {
            SendRequestAsync(data).Wait();
        }

        protected async Task ReadBufAsync(byte[] buf)
        {
            int leftToRead = buf.Length;
            while (leftToRead > 0)
            {
                leftToRead -= await tcpStream.ReadAsync(buf, buf.Length - leftToRead, leftToRead);
            }
        }

        private static byte LoadByte(byte[] bytes, int pos)
        {
            return bytes[pos];
        }

        private static ushort LoadUshort(byte[] data, int pos)
        {
            return (ushort)(((((int)(data[pos])) & 0xff) << 8) | ((((int)(data[pos + 1])) & 0xff)));
        }

        private static short LoadInt16(byte[] data, int pos)
        {
            return (short)(((((int)(data[pos])) & 0xff) << 8) | ((((int)(data[pos + 1])) & 0xff)));
        }

        private static GroupAddr LoadGroupAddr(byte[] data, int pos)
        {
            return new GroupAddr(LoadUshort(data, pos));
        }

        private static KNXAddr LoadKNXAddr(byte[] data, int pos)
        {
            return new KNXAddr(LoadUshort(data, pos));
        }

        private static void CheckProtocol(byte[] data, int protocol, int minPacketLen)
        {
            if (((((((int)(data[0])) & 0xff) << 8) | ((((int)(data[1])) & 0xff)))) != protocol || data.Length < minPacketLen)
                throw new ProtocolViolationException();
        }

        private static int StoreUshort(byte[] ibuf, int pos, ushort value)
        {
            ibuf[pos] = (byte)((value >> 8) & 0xff);
            ibuf[pos + 1] = (byte)(value & 0xff);
            return pos + 2;
        }
        private static int StoreByte(byte[] ibuf, int pos, byte value)
        {
            ibuf[pos] = value;
            return pos + 1;
        }

        private async Task<byte[]> DoProtocol(int minResponseLen, ushort protocol)
        {
            return await DoProtocol(new byte[2], minResponseLen, protocol);
        }

        private async Task<byte[]> DoProtocol(ushort protocol)
        {
            return await DoProtocol(new byte[2], 2, protocol);
        }

        private async Task<byte[]> DoProtocolNoCheck(byte[] ibuf, int minResponseLen, ushort protocol)
        {
            var pos = StoreUshort(ibuf, 0, protocol);
            await SendRequestAsync(ibuf);
            var data = await GetRequestAsync();
            if (data.Length < minResponseLen)
                throw new ProtocolViolationException();
            return data;
        }

        private async Task<byte[]> DoProtocolNoCheck(int minResponseLen, ushort protocol)
        {
            var ibuf = new byte[2];
            return await DoProtocolNoCheck(ibuf, minResponseLen, protocol);
        }

        private async Task<byte[]> DoProtocol(byte[] ibuf, int minResponseLen, ushort protocol)
        {
            var data = await DoProtocolNoCheck(ibuf, minResponseLen, protocol);
            CheckProtocol(data, protocol, minResponseLen);
            return data;
        }

        private async Task<byte[]> DoProtocol_Byte(int minResponseLen, ushort protocol, byte arg1)
        {
            byte[] ibuf = new byte[3];
            StoreByte(ibuf, 2, arg1);
            return await DoProtocol(ibuf, minResponseLen, protocol);
        }
        private async Task<byte[]> DoProtocol_ByteByte(int minResponseLen, ushort protocol, byte arg1, byte arg2)
        {
            byte[] ibuf = new byte[4];
            StoreByte(ibuf, 2, arg1);
            StoreByte(ibuf, 3, arg2);
            return await DoProtocol(ibuf, minResponseLen, protocol);
        }
        private async Task<byte[]> DoProtocol_Ushort(int minResponseLen, ushort protocol, ushort arg1)
        {
            byte[] ibuf = new byte[4];
            StoreUshort(ibuf, 2, arg1);
            return await DoProtocol(ibuf, minResponseLen, protocol);
        }
        private async Task<byte[]> DoProtocol_UshortByte(int minResponseLen, ushort protocol, ushort arg1, byte arg2)
        {
            byte[] ibuf = new byte[5];
            StoreUshort(ibuf, 2, arg1);
            StoreByte(ibuf, 4, arg2);
            return await DoProtocol(ibuf, minResponseLen, protocol);
        }
        private async Task<byte[]> DoProtocol_UshortUshort(int minResponseLen, ushort protocol, ushort arg1, ushort arg2)
        {
            byte[] ibuf = new byte[6];
            StoreUshort(ibuf, 2, arg1);
            StoreUshort(ibuf, 4, arg2);
            return await DoProtocol(ibuf, minResponseLen, protocol);
        }

        protected async Task<byte[]> GetRequestAsync()
        {
            byte[] head = new byte[2];
            await ReadBufAsync(head);
            int len = (((((int)(head[0])) & 0xff) << 8) | ((((int)(head[1])) & 0xff)));
            byte[] data = new byte[len];
            await ReadBufAsync(data);
            return data;
        }

        private static byte[] MakeRequest(int protocol)
        {
            return new[] { (byte)((protocol >> 8) & 0xff), (byte)(protocol & 0xff) };
        }
        private static byte[] MakeRequest(int protocol, ushort param1)
        {
            byte[] ibuf = new byte[4];
            ibuf[0] = (byte)((protocol >> 8) & 0xff);
            ibuf[1] = (byte)(protocol & 0xff);
            ibuf[2] = (byte)((param1 >> 8) & 0xff);
            ibuf[2 + 1] = (byte)(param1 & 0xff);
            return ibuf;
        }
        private static byte[] MakeRequest(int protocol, ushort param1, ushort param2)
        {
            byte[] ibuf = new byte[6];
            ibuf[0] = (byte)((protocol >> 8) & 0xff);
            ibuf[1] = (byte)(protocol & 0xff);
            ibuf[2] = (byte)((param1 >> 8) & 0xff);
            ibuf[2 + 1] = (byte)(param1 & 0xff);
            ibuf[4] = (byte)((param2 >> 8) & 0xff);
            ibuf[4 + 1] = (byte)((param2) & 0xff);
            return ibuf;
        }

        protected byte[] GetRequest()
        {
            return GetRequestAsync().Result;
        }

        public void Close()
        {
            tcpClient.Client.Shutdown(SocketShutdown.Both);
            tcpStream.Close();
        }

        public void Close_sync()
        {
            try
            {
                Reset();
            }
            catch (ApplicationException)
            {
            }
            Close();
        }

        public async Task<byte[]> GetAPDUAsync()
        {
            var data = await GetRequestAsync();
            CheckProtocol(data, 0x0025, 2);
            return data.Skip(2).ToArray();
        }

        public byte[] GetAPDU()
        {
            return GetAPDUAsync().Result;
        }

        public async Task<Tuple<byte[], KNXAddr>> GetAPDUSrcAsync()
        {
            var data = await GetRequestAsync();
            CheckProtocol(data, 0x0025, 4);
            return new Tuple<byte[], KNXAddr>(data.Skip(4).ToArray(), LoadKNXAddr(data, 2));
        }

        public byte[] GetAPDUSrc(out KNXAddr src)
        {
            var r = GetAPDUSrcAsync().Result;
            src = r.Item2;
            return r.Item1;
        }

        public async Task<byte[]> GetBusmonitorPacketAsync()
        {
            var data = await GetRequestAsync();
            CheckProtocol(data, 0x0014, 2);
            return data.Skip(2).ToArray();
        }

        public byte[] GetBusmonitorPacket()
        {
            return GetBusmonitorPacketAsync().Result;
        }

        public async Task<Tuple<byte[],KNXAddr,GroupAddr>> GetGroupSrcAsync()
        {
            var data = await GetRequestAsync();
            CheckProtocol(data, 0x0027, 6);
            return new Tuple<byte[], KNXAddr, GroupAddr>(
                data.Skip(6).ToArray(),
                LoadKNXAddr(data, 2), 
                LoadGroupAddr(data, 4));

        }

        public byte[] GetGroupSrc(out KNXAddr src, out GroupAddr dest)
        {
            var r = GetGroupSrcAsync().Result;
            src = r.Item2;
            dest = r.Item3;
            return r.Item1;
        }

        public async Task<Tuple<byte[], KNXAddr>> GetTPDUAsync()
        {
            var data = await GetRequestAsync();
            CheckProtocol(data, 0x0025, 4);
            return new Tuple<byte[], KNXAddr>(data.Skip(4).ToArray(), LoadKNXAddr(data, 2));
        }


        public byte[] GetTPDU(out KNXAddr src)
        {
            var r = GetTPDUAsync().Result;
            src = r.Item2;
            return r.Item1;
        }

        public async Task CacheClearAsync()
        {
            await DoProtocol(2, 0x0027);
        }


        public void CacheClear()
        {
            CacheClearAsync().Wait();
        }

        public async Task CacheDisableAsync()
        {
            await DoProtocol(2, 0x0071);
        }

        public void CacheDisable()
        {
            CacheDisableAsync().Wait();
        }

        public async Task CacheEnableAsync()
        {
            await DoProtocol(2, 0x0070);
        }

        public void CacheEnable()
        {
            CacheEnableAsync().Wait();
        }

        public async Task<Tuple<byte[], KNXAddr>> CacheReadAsync(GroupAddr dest)
        {
            await SendRequestAsync(MakeRequest(0x0075, dest.Value));
            var data = await GetRequestAsync();
            CheckProtocol(data, 0x0075, 6);
            if (LoadInt16(data, 4) == 0)
                throw new ApplicationException("Device not found");
            if (data.Length <= 6)
                throw new ApplicationException("Entry not found");
            return new Tuple<byte[], KNXAddr>(data.Skip(6).ToArray(), LoadKNXAddr(data, 2));
        }

        public byte[] CacheRead(GroupAddr dest, out KNXAddr src)
        {
            var r = CacheReadAsync(dest).Result;
            src = r.Item2;
            return r.Item1;
        }

        public async Task<Tuple<byte[], KNXAddr>> CacheReadSyncAsync(GroupAddr dest, ushort age)
        {
            var ibuf = MakeRequest(0x0074, dest.Value, age);
            await SendRequestAsync(ibuf);
            var data = await GetRequestAsync();
            CheckProtocol(data, 0x0074, 6);
            if (LoadInt16(data, 4) == 0)
                throw new ApplicationException("Device not found");
            if (data.Length <= 6)
                throw new ApplicationException("Entry not found");
            return new Tuple<byte[], KNXAddr>(data.Skip(6).ToArray(), LoadKNXAddr(data, 2));
        }

        public byte[] CacheReadSync(GroupAddr dest, ushort age, out KNXAddr src)
        {
            var r = CacheReadSyncAsync(dest, age).Result;
            src = r.Item2;
            return r.Item1;
        }

        public async Task CacheRemoveAsync(GroupAddr dest)
        {
            await DoProtocol(0x0073);
        }

        public void CacheRemove(GroupAddr dest)
        {
            CacheRemoveAsync(dest).Wait();
        }

        public async Task<Tuple<byte[], ushort>> CacheLastUpdatesAsync(ushort start, byte timeout)
        {
            await SendRequestAsync(MakeRequest(0x0076, start, timeout));
            var data = await GetRequestAsync();
            CheckProtocol(data, 0x0076, 4);
            return new Tuple<byte[], ushort>(data.Skip(4).ToArray(), LoadUshort(data, 2));
        }

        public byte[] CacheLastUpdates(ushort start, byte timeout, out ushort ende)
        {
            var r = CacheLastUpdatesAsync(start, timeout).Result;
            ende = r.Item2;
            return r.Item1;
        }

        public async Task<int> LoadImageAsync(byte[] image)
        {
            byte[] ibuf = new byte[2 + image.Length];
            StoreUshort(ibuf, 0, 0x0063);
            image.CopyTo(ibuf, 2);
            await SendRequestAsync(ibuf);
            var data = await GetRequestAsync();
            CheckProtocol(data, 0x0063, 4);
            return LoadInt16(data, 2);
        }

        public int LoadImage(byte[] image)
        {
            return LoadImageAsync(image).Result;
        }

        public async Task<int> MCAuthorizeAsync(byte[] key)
        {
            if (key.Length != 4) throw new IndexOutOfRangeException("key is not 4 bytes long");
            byte[] ibuf = new byte[6];
            StoreUshort(ibuf, 0, 0x0057);
            key.CopyTo(ibuf, 2);
            await SendRequestAsync(ibuf);
            var data = await GetRequestAsync();
            CheckProtocol(data, 0x0057, 3);
            return (int)LoadByte(data, 2); 
        }

        public int MCAuthorize(byte[] key)
        {
            return MCAuthorizeAsync(key).Result;
        }

        public async Task MCConnectAsync(KNXAddr dest)
        {
            await DoProtocol_Ushort(2, 0x0050, dest.Value);
        }

        public void MCConnect(KNXAddr dest)
        {
            MCConnectAsync(dest).Wait();
        }

        public async Task MCIndividualOpenAsync(KNXAddr dest)
        {
            await DoProtocol_Ushort(2, 0x0049, dest.Value);
        }

        public void MCIndividualOpen(KNXAddr dest)
        {
            MCIndividualOpenAsync(dest).Wait();
        }

        public async Task<int> MCGetMaskVersionAsync()
        {
            return LoadUshort(await DoProtocol(4, 0x0059), 2);
        }

        public int MCGetMaskVersion()
        {
            return MCGetMaskVersionAsync().Result;
        }

        public async Task<int> MCGetPEITypeAsync()
        {
            return LoadUshort(await DoProtocol(4, 0x0055), 2);
        }

        public int MCGetPEIType()
        {
            return MCGetPEITypeAsync().Result;
        }

        public async Task MCSetProgmodeAsync(bool progmode)
        {
            await DoProtocol_Byte(2, 0x0060, (byte) (progmode ? 1 : 0));
        }

        public void MCSetProgmode(bool progmode)
        {
            MCSetProgmodeAsync(progmode).Wait();
        }

        public async Task MCProgmodeOffAsync()
        {
            await MCSetProgmodeAsync(false);
        }

        public void MCProgmodeOff()
        {
            MCProgmodeOffAsync().Wait();
        }

        public async Task MCProgmodeOnAsync()
        {
            await MCSetProgmodeAsync(true);
        }

        public void MCProgmodeOn()
        {
            MCProgmodeOnAsync().Wait();
        }

        public async Task<bool> MCProgmodeStatusAsync()
        {
            return LoadByte(await DoProtocol_Byte(3, 0x0060, (byte) 3), 2) != 0;
        }

        public bool MCProgmodeStatus()
        {
            return MCProgmodeStatusAsync().Result;
        }

        public async Task MCProgmodeToggleAsync()
        {
            await DoProtocol_Byte(2, 0x0060, (byte) 2);
        }

        public void MCProgmodeToggle()
        {
            MCProgmodeToggleAsync().Wait();
        }

        public async Task<Tuple<byte, ushort, byte>> MCPropertyDescAsync(byte obj, byte propertyno)
        {
            var data = await DoProtocol_ByteByte(6, 0x0061, (byte) obj, (byte) propertyno);
            return new Tuple<byte, ushort, byte>( data[2], LoadUshort(data, 3), data[5]);
        }

        public void MCPropertyDesc(byte obj, byte propertyno, out byte proptype, out ushort max_nr_of_elem,
            out byte access)
        {
            var r = MCPropertyDescAsync(obj, propertyno).Result;
            proptype = r.Item1;
            max_nr_of_elem = r.Item2;
            access = r.Item3;
        }

        public async Task<byte[]> MCPropertyReadAsync(byte obj, byte propertyno, ushort start, byte nr_of_elem)
        {
            var ibuf = new byte[7];
            StoreByte(ibuf, 2, obj);
            StoreByte(ibuf, 3, propertyno);
            StoreUshort(ibuf, 4, start);
            StoreByte(ibuf, 6, nr_of_elem);
            var data = await DoProtocol(ibuf, 2, 0x0053);
            return data.Skip(2).ToArray();
        }

        public byte[] MCPropertyRead(byte obj, byte propertyno, ushort start, byte nr_of_elem)
        {
            return MCPropertyReadAsync(obj, propertyno, start, nr_of_elem).Result;
        }

        public async Task<byte[]> MCPropertyScanAsync()
        {
            var data = await DoProtocol(0x0062);
            return data.Skip(2).ToArray();
        }

        public byte[] MCPropertyScan()
        {
            return MCPropertyScanAsync().Result;
        }

        public async Task<byte[]> MCPropertyWriteAsync(byte obj, byte propertyno, ushort start, byte nr_of_elem, byte[] buf)
        {
            var ibuf = new byte[7 + buf.Length];
            StoreByte(ibuf, 2, obj);
            StoreByte(ibuf, 3, propertyno);
            StoreUshort(ibuf, 4, start);
            StoreByte(ibuf, 6, nr_of_elem);
            buf.CopyTo(ibuf, 7);
            var data = await DoProtocol(ibuf, 2, 0x0054);
            return data.Skip(2).ToArray();
        }

        public byte[] MCPropertyWrite(byte obj, byte propertyno, ushort start, byte nr_of_elem, byte[] buf)
        {
            return MCPropertyWriteAsync(obj, propertyno, start, nr_of_elem, buf).Result;
        }

        public async Task<short> MCReadACAsync(byte channel, byte count)
        {
            var data = await DoProtocol_ByteByte(4, 0x0056, channel, count);
            return LoadInt16(data, 2);
        }

        public short MCReadAC(byte channel, byte count)
        {
            return MCReadACAsync(channel, count).Result;
        }

        public async Task<byte[]> MCReadAsync(KNXAddr addr, int buf_len)
        {
            var data = await DoProtocol_UshortUshort(2, 0x0051, addr.Value, (ushort)buf_len);
            return data.Skip(2).ToArray();
        }

        public byte[] MCRead(KNXAddr addr, int buf_len)
        {
            return MCReadAsync(addr, buf_len).Result;
        }

        public async Task MCRestartAsync()
        {
            await DoProtocol(0x005a);
        }

        public void MCRestart()
        {
            MCRestartAsync().Wait();
        }

        public async Task MCSetKeyAsync(byte[] key, byte level)
        {
            if (key.Length != 4) throw new ArgumentException("key is not 4 bytes long");
            var ibuf = new byte[7];
            StoreUshort(ibuf, 0, 0x0058);
            key.CopyTo(ibuf, 2);
            StoreByte(ibuf, 6, level);
            await SendRequestAsync(ibuf);
            var data = await GetRequestAsync();
            if (LoadInt16(data, 0) == 0x0002)
                throw new AccessViolationException();
            CheckProtocol(data, 0x0058, 2);
        }

        public void MCSetKey(byte[] key, byte level)
        {
            MCSetKeyAsync(key, level).Wait();
        }

        public async Task MCWriteAsync(KNXAddr addr, byte[] buf)
        {
            var ibuf = new byte[6 + buf.Length];
            StoreUshort(ibuf, 0, 0x0052);
            StoreUshort(ibuf, 2, addr.Value);
            StoreUshort(ibuf, 4, (ushort)buf.Length);
            buf.CopyTo(ibuf, 6);
            await SendRequestAsync(ibuf);
            var data = await GetRequestAsync();
            if (LoadInt16(data, 0) == 0x0044)
                throw new IOException();
            CheckProtocol(data, 0x0052, 2);
        }

        public void MCWrite(KNXAddr addr, byte[] buf)
        {
            MCWriteAsync(addr, buf).Wait();
        }

        public async Task MCWritePlainAsync(KNXAddr addr, byte[] buf)
        {
            var ibuf = new byte[6 + buf.Length];
            StoreUshort(ibuf, 0, 0x005b);
            StoreUshort(ibuf, 2, addr.Value);
            StoreUshort(ibuf, 4, (ushort) buf.Length);
            buf.CopyTo(ibuf, 6);
            await DoProtocol(ibuf, 2, 0x005b);
        }

        public void MCWritePlain(KNXAddr addr, byte[] buf)
        {
            MCWritePlainAsync(addr, buf).Wait();
        }

        public async Task<ushort> MGetMaskVersionAsync(KNXAddr dest)
        {
            var data = await DoProtocol_Ushort(4, 0x0031, dest.Value);
            return LoadUshort(data, 2);
        }

        public ushort MGetMaskVersion(KNXAddr dest)
        {
            return MGetMaskVersionAsync(dest).Result;
        }

        public async Task MProgmodeOffAsync(KNXAddr dest)
        {
            await DoProtocol_UshortByte(2, 0x0030, dest.Value, (byte) 0);
        }

        public void MProgmodeOff(KNXAddr dest)
        {
            MProgmodeOffAsync(dest).Wait();
        }

        public async Task MProgmodeOnAsync(KNXAddr dest)
        {
            await DoProtocol_UshortByte(2, 0x0030, dest.Value, (byte) 1);
        }

        public void MProgmodeOn(KNXAddr dest)
        {
            MProgmodeOnAsync(dest).Wait();
        }

        public async Task<bool> MProgmodeStatusAsync(KNXAddr dest)
        {
            var data = await DoProtocol_UshortByte(3, 0x0030, dest.Value, (byte) 3);
            return LoadByte(data, 2) != 0;
        }

        public bool MProgmodeStatus(KNXAddr dest)
        {
            return MProgmodeStatusAsync(dest).Result;
        }

        public async Task MProgmodeToggleAsync(KNXAddr dest)
        {
            await DoProtocol_UshortByte(2, 0x0030, dest.Value, (byte) 2);
        }

        public void MProgmodeToggle(KNXAddr dest)
        {
            MProgmodeToggleAsync(dest).Wait();
        }

        public async Task<byte[]> MReadIndividualAddressesAsync()
        {
            return (await DoProtocol(0x0032)).Skip(2).ToArray();
        }

        public byte[] MReadIndividualAddresses()
        {
            return MReadIndividualAddressesAsync().Result;
        }

        public async Task MWriteIndividualAddressesAsync(KNXAddr dest)
        {
            var ibuf = new byte[4];
            StoreUshort(ibuf, 2, dest.Value);
            var data = await DoProtocolNoCheck(ibuf, 2, 0x0040);
            var code = LoadUshort(data, 0);
            if (code == 0x0041)
                throw new ApplicationException("Address in use");
            if (code == 0x0042)
                throw new ApplicationException("Address not available");
            if (code == 0x0043)
                throw new TimeoutException();
            if (code != 0x0040)
                throw new ProtocolViolationException();
        }

        public void MWriteIndividualAddresses(KNXAddr dest)
        {
            MWriteIndividualAddressesAsync(dest).Wait();
        }

        public async Task OpenBusMonitorAsync()
        {
            var data = await DoProtocolNoCheck(2, 0x0010);
            var code = LoadUshort(data, 0);
            if (code == 0x0001)
                throw new ApplicationException("Resource busy");
            if (code != 0x0010)
                throw new ProtocolViolationException();
        }

        public void OpenBusMonitor()
        {
            OpenBusMonitorAsync().Wait();
        }

        public async Task OpenBusMonitorTextAsync()
        {
            var data = await DoProtocolNoCheck(2, 0x0011);
            var code = LoadUshort(data, 0);
            if (code == 0x0001)
                throw new ApplicationException("Resource busy");
            if (code != 0x0011)
                throw new ProtocolViolationException();
        }

        public void OpenBusMonitorText()
        {
            OpenBusMonitorTextAsync().Wait();
        }

        public async Task OpenGroupSocketAsync(bool writeOnly)
        {
            await DoProtocol_UshortByte(2, 0x0026, (ushort)0, (byte)(writeOnly ? 0xff : 0));
        }


        public void OpenGroupSocket(bool writeOnly)
        {
            OpenGroupSocketAsync(writeOnly).Wait();
        }

        public async Task OpenTBroadcastAsync(bool writeOnly)
        {
            await DoProtocol_UshortByte(2, 0x0023, (ushort)0, (byte)(writeOnly ? 0xff : 0));
        }

        public void OpenTBroadcast(bool writeOnly)
        {
            OpenTBroadcastAsync(writeOnly).Wait();
        }

        public async Task OpenTConnectionAsync(KNXAddr dest)
        {
            await DoProtocol_UshortByte(2, 0x0020, dest.Value, (byte)0);
        }

        public void OpenTConnection(KNXAddr dest)
        {
            OpenTConnectionAsync(dest).Wait();
        }

        public async Task OpenTGroupAsync(GroupAddr dest, bool writeOnly)
        {
            await DoProtocol_UshortByte(2, 0x0022, dest.Value, (byte)((writeOnly) ? 0xff : 0));
        }

        public void OpenTGroup(GroupAddr dest, bool writeOnly)
        {
            OpenTGroupAsync(dest, writeOnly).Wait();
        }

        public async Task OpenTIndividualAsync(KNXAddr dest, bool writeOnly)
        {
            await DoProtocol_UshortByte(2, 0x0021, dest.Value, (byte) ((writeOnly) ? 0xff : 0));
        }

        public async Task OpenTTPDUAsync(KNXAddr src)
        {
            await DoProtocol_UshortByte(2, 0x0024, src.Value, (byte) 0);
        }

        public void OpenTTPDU(KNXAddr src)
        {
            OpenTTPDUAsync(src).Wait();
        }

        public async Task OpenVBusmonitorAsync()
        {
            var data = await DoProtocolNoCheck(2, 0x0012);
            var code = LoadUshort(data, 0);
            if (code == 0x0001)
                throw new ApplicationException("Resource busy");
            if (code != 0x0012)
                throw new ProtocolViolationException();
        }

        public void OpenVBusmonitor()
        {
            OpenVBusmonitorAsync().Wait();
        }

        public async Task OpenVBusmonitorTextAsync()
        {
            var data = await DoProtocolNoCheck(2, 0x0013);
            var code = LoadUshort(data, 0);
            if (code == 0x0001)
                throw new ApplicationException("Resource busy");
            if (code != 0x0013)
                throw new ProtocolViolationException();
        }

        public void OpenVBusmonitorText()
        {
            OpenVBusmonitorTextAsync().Wait();
        }

        public async Task ResetAsync()
        {
            await SendRequestAsync(MakeRequest(0x0004));
            var data = await GetRequestAsync();
            CheckProtocol(data, 0x0004, 2);
        }

        public void Reset()
        {
            ResetAsync().Wait();
        }


        public async Task SendAPDUAsync(byte[] data)
        {
            if (data.Length < 2) throw new IndexOutOfRangeException("data too short");
            var ibuf = new byte[2 + data.Length];
            StoreUshort(ibuf, 0, 0x0025);
            data.CopyTo(ibuf, 2);
            await SendRequestAsync(ibuf);
        }

        public void SendAPDU(byte[] data)
        {
            SendAPDUAsync(data).Wait();
        }

        public async Task SendGroupAsync(GroupAddr dest, byte[] data)
        {
            var ibuf = new byte[4 + data.Length];
            StoreUshort(ibuf, 0, 0x0027);
            StoreUshort(ibuf, 2, dest.Value);
            data.CopyTo(ibuf, 4);
            await SendRequestAsync(ibuf);
        }

        public void SendGroup(GroupAddr dest, byte[] data)
        {
            SendGroupAsync(dest, data).Wait();
        }

        public async Task SendTPDUAsync(KNXAddr dest, byte[] data)
        {
            var ibuf = new byte[4 + data.Length];
            StoreUshort(ibuf, 0, 0x0025);
            StoreUshort(ibuf, 2, dest.Value);
            data.CopyTo(ibuf, 4);
            await SendRequestAsync(ibuf);
        }

        public void SendTPDU(KNXAddr dest, byte[] data)
        {
            SendTPDUAsync(dest, data).Wait();
        }

    }

}

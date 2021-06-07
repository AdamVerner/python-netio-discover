import logging
from collections import namedtuple
from typing import Iterable, List
import netifaces
import socket
from multiprocessing.pool import ThreadPool

SEND_PORT = 62387
SEND_DATA = b'\x01\xec\x00'
RECV_PORT = 62386


class NetioDiscover(object):

    Interface = namedtuple('Interface', 'addr netmask broadcast')

    def __init__(self, interfaces=None):
        """
        :param interfaces: list of interface names to use for discovery, interface name in Linux, GUID on windows.
        """

        self.log = logging.getLogger('discover')
        self.devices = []

        self.interfaces = list(self._get_ifaddresses(only=interfaces))
        print(*self.interfaces, sep='\n')

    @staticmethod
    def _get_ifaddresses(only: List[str] = None) -> Iterable[Interface]:
        """
        Get information about all accessible network interfaces.

        On windows the only parameter takes GUID instead of interface name.

        :param only: get addresses only of these NICs. e.g. 'eth0', ...
        :return: list of all available addresses for all provided NICs
        """
        for iface in netifaces.interfaces():

            # TODO we could use registry entries to get usable names on windows
            if only is not None and iface not in only:
                continue

            addresses = netifaces.ifaddresses(iface)
            for nic in addresses.get(netifaces.AF_INET, []):
                # skip localhost
                if nic.get('addr') == '127.0.0.1':
                    continue
                yield NetioDiscover.Interface(**nic)

    def discover_devices(self, timeout=3):
        """
        Discover NETIO devices on all available network interfaces.
        Listen for defined timeout at interfaces specified in __init__ and return Dictionary with all found devices.
        """
        self.devices.clear()

        def worker(interface):
            logging.info(f'polling {interface}')
            devs = list(self._find_devices_on_interface(interface, timeout=timeout))
            self.devices += devs
            logging.info(f'found {len(devs)} devices on  "{interface}"')

        pool = ThreadPool()

        for iface in self.interfaces:
            pool.apply_async(worker, (iface, ))

        pool.close()
        pool.join()

        return self.devices

    # backwards compatibility
    getDevicesLinux = discover_devices

    @staticmethod
    def _find_devices_on_interface(interface: Interface, timeout=1) -> Iterable[dict]:
        """
        Generator containing all devices found on specified interface.
        Device is specified as dict returned by parseDeviceInfo.

        :param interface: named tuple containing addr and broadcast.
        :param timeout: time to wait for device response.
        :return: generator containing all devices found. The devices are added to generator as they're discovered.
        """

        # prepare the listener
        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # listen on UDP
        if hasattr(socket, 'SO_REUSEPORT'):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        listener.settimeout(timeout)
        listener.bind((interface.addr, RECV_PORT))
        logging.debug(f'listener bound to {(interface.addr, RECV_PORT)}')

        # send the discover broadcast
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        if hasattr(socket, 'SO_REUSEPORT'):
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sender.sendto(SEND_DATA, (interface.broadcast, SEND_PORT))
        sender.close()
        logging.debug(f'magic packet sent to {(interface.broadcast, SEND_PORT)}')

        # receive data
        while True:
            try:
                data, addr = listener.recvfrom(1024)
            except socket.timeout:
                break
            logging.debug(f'received packet from "{addr}: "{data}"')
            if not data:
                break
            yield NetioDiscover.parseDeviceInfo(data)

        listener.close()

    @staticmethod
    def parseDeviceInfo(data):
        """
        Parse NETIO Device information from data payload
        """
        binarydata = bytearray(data)

        if binarydata[0] != 2:
            print('Data are not valid')
            return
        else:
            pass

        i=3
        params = []
        datalen=len(binarydata)
        while i < datalen-1:
            param = {'DATA': []}
            param['FTYPE'] = binarydata[i]
            i += 1
            paramlen = binarydata[i]
            i += 1
            if (i+paramlen) < len(binarydata):
                for j in range(0, paramlen):
                    param['DATA'].append(binarydata[i+j])
            i += paramlen
            params.append(param)

        device = {}

        for item in params:

            if item.get('FTYPE') == 0x01:   #FIRMWARE_VERSION
                device['fwversion'] = ''.join(chr(i) for i in item.get('DATA'))
                continue
            if item.get('FTYPE') == 0x02:   #MAC
                device['mac'] = ':'.join(format(i, '02x') for i in item.get('DATA')).upper()
                continue
            if item.get('FTYPE') == 0x03:   #IP
                device['ip'] = '.'.join(str(i) for i in item.get('DATA'))
                continue
            if item.get('FTYPE') == 0x04:   #NETMASK
                device['mask'] = '.'.join(str(i) for i in item.get('DATA'))
                continue
            if item.get('FTYPE') == 0x05:   #HOSTNAME
                device['hostname'] = ''.join(chr(i) for i in item.get('DATA'))
                continue
            if item.get('FTYPE') == 0x06:   #DHCP
                continue
            if item.get('FTYPE') == 0x07:   #SETUP_STATE
                continue
            if item.get('FTYPE') == 0x08:   #RESULT
                continue
            if item.get('FTYPE') == 0x09:   #PRODUCT
                device['model'] = ''.join(chr(i) for i in item.get('DATA'))
                continue
            if item.get('FTYPE') == 0x0a:   #MANUFACTURER
                device['manufacturer'] = ''.join(chr(i) for i in item.get('DATA'))
                continue
            if item.get('FTYPE') == 0x0b:   #PLATFORM
                device['platform'] = ''.join(chr(i) for i in item.get('DATA'))
                continue
            if item.get('FTYPE') == 0x0c:   #VARIANT
                device['hostname'] = ''.join(chr(i) for i in item.get('DATA'))
                continue
            if item.get('FTYPE') == 0x0d:   #TIMEOUT
                continue
            if item.get('FTYPE') == 0x0e:   #GATEWAY
                continue
            if item.get('FTYPE') == 0x0f:   #DNS
                continue
            if item.get('FTYPE') == 0x12:   #PRETTY_PLATFORM_NAME
                device['platformname'] = ''.join(chr(i) for i in item.get('DATA'))
                continue
            if item.get('FTYPE') == 0x13:   #DEVICE_NAME
                device['devicename'] = ''.join(chr(i) for i in item.get('DATA'))
                continue

        return device


def discover_all(only: List[str] = None):
    nd = NetioDiscover(only)
    return nd.discover_devices(1)


if __name__ == '__main__':

    logging.basicConfig(level=logging.INFO)

    for idx, device in enumerate(discover_all()):
        print(f'({idx}):', device)

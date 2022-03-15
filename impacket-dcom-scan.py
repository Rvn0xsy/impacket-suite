#!/usr/bin/env python3
"""
Author : @Rvn0xsy
Password detection based on DCOM lateral movement requires the target to open port 135
"""
from impacket.dcerpc.v5 import dcomrt
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.examples.utils import parse_target
from impacket import version
from impacket.examples import logger
from impacket.uuid import string_to_bin
import sys
import logging
import argparse
import ipaddress

class RPC_Connect():
    def __init__(self,options) -> None:
        self.__username = options.username
        self.__password = options.password
        self.__domain = options.domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__targets = options.target_list
        self.__timeout = options.timeout
        self.__clsids = list()
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def check_target(self) -> None:
        result = list()
        clsid = '84D586C4-A423-11D2-B943-00C04F79D22F'
        for target in self.__targets:
            try:
                logging.debug("%s -> CLSID : %s " % (target,clsid))
                dcom = dcomrt.DCOMConnection(target, self.__username,self.__password, self.__domain,self.__lmhash,self.__nthash)
                dcom.CoCreateInstanceEx(string_to_bin(clsid), string_to_bin('00020400-0000-0000-C000-000000000046'))
                dce = dcom.get_dce_rpc()
                dce.connect()
                success_msg = "%s\t%s\t%s\t[%s]" % (target,self.__username,self.__password,clsid)
                logging.info(success_msg)
                result.append(success_msg)
            except DCERPCException as err:
                logging.debug(err)
        logging.info("Success Count : %d" % len(result))

if __name__ == '__main__':
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Check RPC Connect")

    parser.add_argument('-username', action='store', help='username',required=True)
    parser.add_argument('-password', action='store', help='password')
    parser.add_argument('-domain', action='store', help='domain name',default='')
    parser.add_argument('-target', action='store', help='target IP address or IP CIDR')
    parser.add_argument('-target-file', action='store', type=argparse.FileType('r'), help='input file with targets (one per line). ')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('connection')
    group.add_argument('-timeout', action='store', default='10', help='socket timeout out when connecting to the target (default 2 sec)')
    group.add_argument('-target-ip', action='store', metavar="ip address", help='IP Address of the target machine. If '
                       'ommited it will use whatever was specified as target. This is useful when target is the NetBIOS '
                       'name and you cannot resolve it')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
 
    options = parser.parse_args()
    
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
    options.target_list = list()

    if options.target is None:
        for line in options.targets.readlines():
            options.target_list.append(line.strip('\r\n'))
    else:
        hosts = list(ipaddress.ip_network(options.target).hosts())
        for host in hosts:
            options.target_list.append(str(host))
    logging.debug("Targets Count : %d " % len(options.target_list))
    if options.password == '' and options.username != '' and options.hashes is None:
        from getpass import getpass
        options.password = getpass("Password:")

    rpc = RPC_Connect(options)
    rpc.check_target()

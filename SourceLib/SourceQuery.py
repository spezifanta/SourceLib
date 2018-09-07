#!/usr/bin/python

#------------------------------------------------------------------------------
# SourceQuery - Python class for querying info from Source Dedicated Servers
# Copyright (c) 2012 Alex Kuhrt <alex@qrt.de>
# Copyright (c) 2010 Andreas Klauer <Andreas.Klauer@metamorpher.de>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#------------------------------------------------------------------------------

"""http://developer.valvesoftware.com/wiki/Server_Queries"""

# TODO: according to spec, packets may be bzip2 compressed.
#       not implemented yet because I couldn't find a server that does this.


import logging
import socket
import time

from buffer import SteamPacketBuffer
from server import Server
from packet import *

PACKET_SIZE = 1400
SINGLE_PACKET_RESPONSE = -1
MULTIPLE_PACKET_RESPONSE = -2


class SourceQueryError(Exception):
    pass


class SourceQuery:
    """
    Example usage:

    import SourceQuery
    server = SourceQuery.SourceQuery('1.2.3.4', 27015)
    print server.ping()
    print server.info()
    print server.players()
    print server.rules()
    """

    def __init__(self, host, port=27015, timeout=1):
        self.logger = logging.getLogger('SourceQuery')
        self.server = Server(socket.gethostbyname(host), port)
        self._timeout = timeout
        self._connect()

    def __del__(self):
        self._connection.close()

    def _connect(self):
        self.logger.info('Connecting to %s', self.server)
        self._connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._connection.settimeout(self._timeout)
        self._connection.connect(self.server.as_tuple())

    def _receive(self, packet_buffer={}):
        response = self._connection.recv(PACKET_SIZE)
        self.logger.debug('Recieved: %s', response)
        packet = SteamPacketBuffer(response)
        response_type = packet.read_long()

        if response_type == SINGLE_PACKET_RESPONSE:
            self.logger.debug('Single packet response')
            return packet

        elif response_type == MULTIPLE_PACKET_RESPONSE:
            self.logger.debugg('Multiple packet response')
            request_id = packet.read_long()  # TODO: compressed?

            if request_id not in packet_buffer:
                packet_buffer.setdefault(request_id, [])

            total_packets = packet.read_byte()
            current_packet_number = packet.read_byte()
            paket_size = packet.read_short()
            packet_buffer[request_id].insert(current_packet_number, packet.read())

            if current_packet_number == total_packets - 1:
                full_packet = PacketBuffer(b''.join(packet_buffer[request_id]))

                if full_packet.read_long() == PACKET_HEAD:
                    return full_packet
            else:
                return self._receive(packet_buffer)
        else:
            self.logger.error('Received invalid response type: %s', response_type)
            raise SourceQueryError('Received invalid response type')

    def _get_challenge(self):
        response = self._send(ChallengeRequest())

        response.is_valid()
        return response.raw

    def _send(self, Paket):
        if isinstance(Paket, Challengeable):
            challenge = self._get_challenge()
            self.logger.debug('Using challenge: %s', challenge)
            Paket.challenge = challenge

        timer_start = time.time()
        self.logger.debug('Paket: %s', Paket.as_bytes())
        self._connection.send(Paket.as_bytes())
        result = self._receive()
        ping = round((time.time() - timer_start) * 1000, 2)
        response = create_response(Paket.class_name(), result, ping)

        if not response.is_valid():
            raise SourceQueryError('Response paket is invalid.')

        return response

    def request(request):
        def wrapper(self):
            response = request(self)
            result = response.result()
            result['server'] = {
                'ip': self.server.ip,
                'port': self.server.port,
                'ping': response.ping
            }
            return result
        return wrapper

    def ping(self):
        """Fake ping request. Send three InfoRequets and calculate an average ping."""
        self.logger.info('Sending fake ping request')
        MAX_LOOPS = 3
        return round(sum(map(lambda ping: self.info().get('server').get('ping'),
                             range(MAX_LOOPS))) / MAX_LOOPS, 2)

    @request
    def info(self):
        """Request basic server information."""
        self.logger.info('Sending info request')
        return self._send(InfoRequest())

    @request
    def players(self):
        """Request player information."""
        self.logger.info('Sending players request')
        return self._send(PlayersRequest())

    @request
    def rules(self):
        """Request server rules."""
        self.logger.info('Sending rules request')
        return self._send(RulesRequest())


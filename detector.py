try:
    import scapy.all as scapy
except KeyboardInterrupt:
    print("[-] CTRL+C.")
    exit()
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import datetime
import time


class Detector():
    def __init__(self, email, password, to_email):
        self.about()
        self.email = email
        self.password = password
        self.to_email = to_email
        self.host = "smtp.gmail.com"
        self.port = 587

    def mac_bul(self, ip):
        arp_claim = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_claim_broadcast = broadcast / arp_claim
        cevap = scapy.srp(arp_claim_broadcast, timeout=1, verbose=False)[0]
        return cevap[0][1].hwsrc

    def sniff(self, interface=""):
        try:
            if interface == "":
                print("[-] Please specify an interface!")
            else:
                scapy.sniff(iface=interface, store=False, prn=self.sniffed_packet)
        except (OSError, ValueError):
            print("[-] There is no such interface.")

    def sniffed_packet(self, paket):
        if paket.haslayer(scapy.ARP) and paket[scapy.ARP].op == 2:
            try:
                gercek_mac = self.mac_bul(paket[scapy.ARP].psrc)
                paket_mac = paket[scapy.ARP].hwsrc
                if paket_mac != gercek_mac:
                    print("[+] you are under attack!")
                    history = datetime.datetime.now()
                    if history.second == 00:
                        self.mailGonder(paket_mac, history)
                        time.sleep(1)
            except IndexError:
                pass

    def uyari(self, mac_adresi, history):
        mail = MIMEMultipart()
        history = history.strftime("%d-%m-%Y %H:%M:%S")
        mail["Subject"] = "You're Under Attack  ~ " + history
        mail["From"] = self.email
        mesaj = """
        <html>
        <head>
              <title>An Attack attempt !!!</title>
        </head>
        <body>
              <h1 align="center">An Attack attempt!!!</h1>
              <p style="font-size:16px;" ><b style="color:lime;background:black"> {mac} </b></h3>  mac  address <b style="color:lime;background:black;"> {history} </b>  on your computer <span style="text-decoration: underline;">ARP Spoofing attack</span> was conducted. </p>
              <br>
        </body >
        </html>
        """.format(mac=mac_adresi, history=history)
        part = MIMEText(mesaj, "html")
        mail.attach(part)
        return mail.as_string()

    def mailGonder(self, mac,history):
        try:
            self.server = smtplib.SMTP(self.host, self.port)
            self.server.ehlo()
            self.server.starttls()
            self.server.ehlo()
            self.server.login(self.email, self.password)
            self.server.sendmail(self.email, self.to_email, self.uyari(mac,history))
            self.server.quit()
        except smtplib.SMTPException:
            print("[-] Sending Mail error!")
        except smtplib.SMTPServerDisconnected:
            print("[-] SMTP Server Disconnected!")
        except smtplib.SMTPConnectError:
            print("[-] SMTP Connection error!")


    def about(self):
        print("# ==============================================================================")


try:
    from_email="coolpix123.coolpix123@gmail.com"
    from_password="coolpix123"
    to_email="coolpix123.coolpix123@gmail.com"
    interface="Wi-Fi"
    detector = Detector(from_email,from_password,to_email)
    detector.sniff(interface)
except KeyboardInterrupt:
    print("[-] CTRL+C.")
    exit()

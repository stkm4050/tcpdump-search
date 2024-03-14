package info

import (
	"net"
	"regexp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	// "fmt"
)

// Detect the packet of entering password.
func DistinctPacket(packet gopacket.Packet, serverIP net.IP, sshClient string, cipher string) (PacketType string) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	// fmt.Println(cipher)

	PacketType = "normal"

	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		ip, _ := ipLayer.(*layers.IPv4)

		// 現在対応しているcipher："3des-cbc, aes128-cbc, aes192-cbc, aes256-cbc, aes128-ctr, aes192-ctr,
		// aes256-ctr, aes128-gcm@openssh.com, aes256-gcm@openssh.com, chacha20-poly1305@openssh.com"

		if tcp.SYN && tcp.ACK { // len(packet.Data()) == 78 &&serverIP.Equal(ip.DstIP)を削除
			PacketType = "SYN/ACK"
		} else if tcp.SYN { //len(packet.Data()) == 74 && && serverIP.Equal(ip.SrcIP)を削除
			PacketType = "SYN"
		} else if tcp.ACK && !tcp.FIN { // 変更箇所 /!tcp.FINを追加　len(packet.Data()) == 66 && && serverIP.Equal(ip.DstIP)を削除
			PacketType = "ACK"
		}

		if regexp.MustCompile(`libssh`).MatchString(sshClient) && tcp.PSH && tcp.ACK {
			if len(packet.Data()) == 118 && serverIP.Equal(ip.SrcIP) {
				PacketType = "SendRequest"
			} else if len(packet.Data()) >= 142 && len(packet.Data()) <= 246 && len(packet.Data()) != 162 && serverIP.Equal(ip.DstIP) {
				PacketType = "SendPassword"
			}
		} else if regexp.MustCompile(`PuTTY`).MatchString(sshClient) && tcp.PSH && tcp.ACK {
			if len(packet.Data()) == 162 && serverIP.Equal(ip.SrcIP) {
				PacketType = "SendRequest"
			} else if len(packet.Data()) == 338 && serverIP.Equal(ip.DstIP) {
				PacketType = "SendPassword"
			}
		} else if regexp.MustCompile("PUTTY").MatchString(sshClient) && tcp.PSH && tcp.ACK {
			if len(packet.Data()) == 146 && serverIP.Equal(ip.SrcIP) {
				PacketType = "SendRequest"
			} else if len(packet.Data()) == 162 && serverIP.Equal(ip.DstIP) {
				PacketType = "SendPassword"
			}
		} else if regexp.MustCompile(`Go`).MatchString(sshClient) && tcp.PSH && tcp.ACK {
			if (len(packet.Data()) == 150 || len(packet.Data()) == 118 || len(packet.Data()) == 166) && serverIP.Equal(ip.SrcIP) {
				PacketType = "SendRequest"
			} else if len(packet.Data()) >= 150 && len(packet.Data()) <= 262 && serverIP.Equal(ip.DstIP) && len(packet.Data()) != 162 {
				PacketType = "SendPassword"
			}
			//以下変更箇所
} else if regexp.MustCompile(`OpenSSH`).MatchString(sshClient) && tcp.PSH && tcp.ACK {
	if cipher == "3des-cbc" {
		if len(packet.Data()) == 134 && serverIP.Equal(ip.SrcIP) {
			PacketType = "SendRequest"
		} else if serverIP.Equal(ip.DstIP) && len(packet.Data()) >= 142 && len(packet.Data()) <= 270 {
			PacketType = "SendPassword"
		}

	} else if cipher == "aes128-cbc" {
		if len(packet.Data()) == 142 && serverIP.Equal(ip.SrcIP) {
			PacketType = "SendRequest"
		} else if serverIP.Equal(ip.DstIP) && len(packet.Data()) >= 142 && len(packet.Data()) <= 270 {
			PacketType = "SendPassword"
		}

	} else if (cipher == "aes192-cbc" || cipher == "aes256-cbc" || cipher == "aes128-ctr" || cipher == "aes192-ctr" || cipher == "aes256-ctr") && tcp.ACK && tcp.PSH {
		if len(packet.Data()) == 142 && serverIP.Equal(ip.SrcIP) {
			PacketType = "SendRequest"
		} else if serverIP.Equal(ip.DstIP) && len(packet.Data()) >= 142 && len(packet.Data()) <= 270 {
			PacketType = "SendPassword"
		}

	} else if (cipher == "aes128-gcm@openssh.com" || cipher == "aes256-gcm@openssh.com") && tcp.PSH && tcp.ACK {
		if len(packet.Data()) == 150 && serverIP.Equal(ip.SrcIP) {
			PacketType = "SendRequest"
		} else if serverIP.Equal(ip.DstIP) && len(packet.Data()) >= 142 && len(packet.Data()) <= 270 {
			PacketType = "SendPassword"
		}

	} else if cipher == "chacha20-poly1305@openssh.com" && tcp.PSH && tcp.ACK {
		if len(packet.Data()) == 130 && serverIP.Equal(ip.SrcIP) {//2月15日変更　変更前142
			PacketType = "SendRequest"
		} else if serverIP.Equal(ip.DstIP) {
			if len(packet.Data()) >= 138 && len(packet.Data()) <= 270 {//2月15日変更　変更前142
				PacketType = "SendPassword"
			}
		}
	}
}

	
		
	}
	return PacketType
}

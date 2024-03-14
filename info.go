package info

import (
	"net"
	"time"
	"log"
	"strconv"
	"strings"

	"github.com/sunwxg/goshark"
)

type PacketInfo struct {
	No            int
	SrcIP         net.IP
	DstIP         net.IP
	SrcPort		  int //送る方のポート番号の指定
	DstPort       int //送られる方のポート番号
	Tsval         int
	Tsecr         int
	Length        int
	PacketTime    time.Time      // パケット送信時刻
	AuthTime      time.Duration  // 認証時間
	InputTime     time.Duration  // パスワード入力時間
	RTT           time.Duration  // RTT
	PassReq       int            // パスワード要求送信を行なっている場合は1，行なっていない場合は0．
	SYN           int            // SYNパケット
	ACK           int            // ACKパケット
	Cipher        string         // 使用しているcipherを格納．
	SshClient     string         // 使用されているSSHクライアントを格納
	CountryName   string
	Latitude      float64
	Longitude     float64
}




func PacketInformation (d *goshark.Decoder, serverIP net.IP, packet [260000]PacketInfo, i int) (p PacketInfo, WsExpert string) {
	f, err := d.NextPacket()
	if err != nil {
		log.Println("get packet fail:", err)
	}

	n, _ := f.Iskey("num")
	p.No, _ = strconv.Atoi(n)

	src, _ := f.Iskey("ip.src")
	dst, _ := f.Iskey("ip.dst")

	p.SrcIP = net.ParseIP(src)
	p.DstIP = net.ParseIP(dst)

	sport,_ := f.Iskey("tcp.srcport")
	dport,_ := f.Iskey("tcp.dstport")

	p.SrcPort,_=strconv.Atoi(sport)
	p.DstPort,_=strconv.Atoi(dport)

	val, _ := f.Iskey("tcp.options.timestamp.tsval")
	ecr, _ := f.Iskey("tcp.options.timestamp.tsecr")

	p.Tsval, _ = strconv.Atoi(val)
	p.Tsecr, _ = strconv.Atoi(ecr)

	l, _ := f.Iskey("len")
	p.Length, _ = strconv.Atoi(l)
	
	t, _ := f.Iskey("timestamp")
	p.PacketTime, _ = time.Parse("Jan  2, 2006 15:04:05 MST", t)

	WsExpert, _ = f.Iskey("_ws.expert")


	// SSHクライアント情報の取得
	var okSshClient bool
	p.SshClient, okSshClient = f.Iskey("ssh.protocol")

	if ! okSshClient {
		for m := i-1; m > 0; m-- {
			if p.SrcIP.Equal(serverIP) {
				if len(packet[m].SshClient) > 0 && p.DstIP.Equal(packet[m].SrcIP) {
					p.SshClient = packet[m].SshClient
					break
				}
			} else {
				if len(packet[m].SshClient) > 0 && p.SrcIP.Equal(packet[m].SrcIP) {
					p.SshClient = packet[m].SshClient
					break
				}
			}
		}
	}
	
	// Cipher取得
	valueClient, okClient := f.Iskey("ssh.encryption_algorithms_client_to_server")
	valueServer, okServer  := f.Iskey("ssh.encryption_algorithms_server_to_client")

	// cipherを`,'で区切って配列に格納．
	cipherClientList := strings.Split(valueClient, ",")
	cipherServerList := strings.Split(valueServer, ",")

	if okClient && okServer {
		status := 0

		// CLient側，Server側それぞれで使用できるcipherのリストの照合を行う．
		// 一致した時点で終了．
		for s := 0; s < len(cipherClientList); s ++ {
			for t := 0; t < len(cipherServerList); t ++ {
				if cipherClientList[s] == cipherServerList[t] { 
					p.Cipher = cipherClientList[s]
					status = 1
					break
				}

				if status == 1 {
					break
				}
			}
		}
		
	} else {
		for m := i-1; m > 0; m-- {
			// client >> serverのCipherが通信には使用される．
			if p.SrcIP.Equal(serverIP) {
				if (len(packet[m].Cipher) > 0 && p.DstIP.Equal(packet[m].SrcIP)) {
					p.Cipher = packet[m].Cipher
					break
				} 
			} else {
				if (len(packet[m].Cipher) > 0 && p.SrcIP.Equal(packet[m].SrcIP)) {
					p.Cipher = packet[m].Cipher
					break
				} 
	
			}
		}

	}
	return p, WsExpert
}







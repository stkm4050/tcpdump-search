package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"mylib/geoip"
	"mylib/json"
	info "mylib/mypkg"
	"net"
	"regexp"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sunwxg/goshark"
)

var (
	// pcapFile string ="../packet/honeypot/dump/2022-11/port22-202211150000.dump"
	// pcapFile string ="../honeypot-dump/2022-11/port22-202211290000.dump
	handle *pcap.Handle
	err    error
)

func main() {
	start := time.Now()
	pcapFile := flag.String("r", "none", "pcapfile")
	server := flag.String("ip", "10.1.152.2", "severIP") // eastusAzureのipアドレス13.72.81.141 ハニポのipアドレス10.1.138.100,7.4のipアドレス10.1.152.2
	flag.Parse()
	serverIP := net.ParseIP(*server)

	// fmt.Println(serverIP)

	handle, err = pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var (
		p        [260000]info.PacketInfo
		authInfo [10000]json.AuthInfo // jsonに出力するために使用
		IPlist   [3000]json.AttackIP  // 認証を行なった国名，回数を表示するために使用．
		j        int
		WsExpert string // パケット再送の判定に用いる．
	)

	d := goshark.NewDecoder()
	if err := d.DecodeStartWithArgs(*pcapFile, "-o", "ssh.tcp.port:49538"); err != nil {//使用するサーバのポート番号を指定する
		log.Println("Decode start fail:", err)
		return
	}
	defer d.DecodeEnd()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for i := 1; ; i++ {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error:", err)
			continue
		}

		// 認証情報取得
		p[i], WsExpert = info.PacketInformation(d, serverIP, p, i)

		// パケットの種類の判定を行う．
		PacketType := info.DistinctPacket(packet, serverIP, p[i].SshClient, p[i].Cipher)
		// fmt.Printf("PacketType: %s\n", PacketType)
		// fmt.Printf("No.%d  %s  %s  %s\n", p[i].No, p[i].SshClient, p[i].Cipher, PacketType)

		if PacketType == "SYN" {
			p[i].SYN = 1
			// fmt.Printf("<SYN> %s No.%d  %v\n\n", p[i].SrcIP, p[i].No, p[i].PacketTime)

		} else if PacketType == "SYN/ACK" {
			p[i].SYN = 1
			p[i].ACK = 1
			// fmt.Printf("<SYN/ACK> %s No.%d  %v\n\n", p[i].DstIP, p[i].No, p[i].PacketTime)

			// } else if PacketType == "ACK" && p[i-1].SYN == 1 && p[i-1].ACK == 1 {
		} else if PacketType == "ACK" {
			for m := i - 1; m > 0; m-- {
				if p[i].Tsecr == p[m].Tsval && p[m].SYN == 1 && p[m].ACK == 1 {
					for k := m - 1; k > 0; k-- {
						if p[m].Tsecr == p[k].Tsval && p[k].Tsecr == 0 {
							p[i].RTT = (p[i].PacketTime.Sub(p[k].PacketTime)) / 2
							p[i].ACK = 1
							// fmt.Printf("RTT: %s\n", p[i].RTT)
							// fmt.Printf("<ACK> %s No.%d  %v  RTT: %v (SYN: No.%d  SYN/ACK: No.%d ACK: No.%d)\n\n", p[i].SrcIP, p[i].No, p[i].PacketTime, p[i].RTT, p[k].No, p[m].No, p[i].No)
							break
						}
					}
					break
				} else if p[i].Tsecr == p[m].Tsecr {
					break
				}
			}

			// p[i].RTT = p[i].PacketTime.Sub(p[i-2].PacketTime) / 2
			// p[i].ACK = 1

		} else if PacketType == "SendRequest" {
			// パスワード要求送信を行なっているため．
			p[i].PassReq = 1

			fmt.Printf("\x1b[43m%s\x1b[0m\n", "-----Request of password------")
			fmt.Printf("\nPacket No.%d\n", i)
			fmt.Printf("Time: %s\n", p[i].PacketTime)
			fmt.Printf("Length: %d byte\n", p[i].Length)
			fmt.Printf("SSH Client: %s\n", p[i].SshClient)
			fmt.Printf("Cipher: %s\n", p[i].Cipher)
			fmt.Printf("<SSH Authentication>\n%s ==>> \x1b[33m%s\x1b[0m\n", p[i].SrcIP, p[i].DstIP)

			// Show connection location.
			// geoip.CountryShow(p[i].DstIP)
			fmt.Printf("\x1b[43m%s\x1b[0m\n", "-----------------------------------------------------------")

		} else if PacketType == "SendPassword" {
			retransmission := 0
			if regexp.MustCompile(`retransmission`).MatchString(WsExpert) {
				retransmission = 1
			}
			// var passreq int
			// パスワード要求送信のパケットを探す．
			for k := i - 1; k > 0; k-- {
				if p[k].PassReq == 1 && p[k].DstIP.Equal(p[i].SrcIP) && p[k].DstPort==p[i].SrcPort{//Requestofpasswordでの配列を確認する→配列内にチェックがついているものがあればそれがパスワード要求のパケット
					p[i].AuthTime = p[i].PacketTime.Sub(p[k].PacketTime)
					// fmt.Printf("No.%d       <<<%v(%v) - %v(%v) = %v>>>\n", p[i].No, p[i].PacketTime, p[i].No, p[k].PacketTime, p[k].No, p[i].AuthTime)
					// passreq = k
					break
				}
			}

			// RTTを表示するために使用．
			var rtt int


			for l := i - 1; l > 0; l-- {
				if p[l].ACK == 1 && p[i].SrcIP.Equal(p[l].SrcIP) && p[l].SrcPort==p[i].DstPort {
					p[i].InputTime = p[i].AuthTime - p[l].RTT
					p[i].RTT = p[l].RTT
					rtt = l
					break
				}

				if l == 1 {
					p[i].InputTime = p[i].AuthTime
				}
			}

			// InputTimeが負の値でない場合のみ
			if p[i].InputTime > 0 && retransmission == 0 {
				p[i].CountryName, p[i].Latitude, p[i].Longitude = geoip.GetCountry(p[i].SrcIP)

				// json出力用にデータ格納
				authInfo[j].No = j + 1
				authInfo[j].PacketNum = p[i].No
				authInfo[j].Time = p[i].PacketTime
				authInfo[j].ClientP = p[i].SrcIP
				authInfo[j].Cipher = p[i].Cipher
				authInfo[j].SshClient = p[i].SshClient
				authInfo[j].AuthTime = float32(p[i].AuthTime) / 1000000
				authInfo[j].InputTime = float32(p[i].InputTime) / 1000000
				authInfo[j].RTT = float32(p[rtt].RTT) / 1000000
				authInfo[j].CountryName = p[i].CountryName
				authInfo[j].Latitude = p[i].Latitude
				authInfo[j].Longitude = p[i].Longitude
				authInfo[j].Distance = json.Distance(p[i].Latitude, p[i].Longitude)

				// IPList, CountryListを出力する場合にコメントアウト

			findIPlist:
				for k := 0; k < len(IPlist); k++ {
					if p[i].SrcIP.Equal(IPlist[k].ClientIP) {
						IPlist[k].ClientIP = p[i].SrcIP
						IPlist[k].CountryName = p[i].CountryName
						IPlist[k].AuthCount = IPlist[k].AuthCount + 1
						IPlist[k].TotalTime = IPlist[k].TotalTime + float32(p[i].InputTime)
						IPlist[k].AverageInputTime = (IPlist[k].TotalTime / float32(IPlist[k].AuthCount)) / 1000000

						if authInfo[j].InputTime > IPlist[k].LongestTime {
							IPlist[k].LongestTime = authInfo[j].InputTime
							break findIPlist

						} else if authInfo[j].InputTime < IPlist[k].ShortestTime {
							IPlist[k].ShortestTime = authInfo[j].InputTime
							break findIPlist
						} else {
							break findIPlist
						}

					} else if len(IPlist[k].ClientIP) == 0 && IPlist[k].LongestTime == 0 && IPlist[k].ShortestTime == 0 {
						IPlist[k].ClientIP = p[i].SrcIP
						IPlist[k].CountryName = p[i].CountryName
						IPlist[k].AuthCount = IPlist[k].AuthCount + 1
						IPlist[k].TotalTime = IPlist[k].TotalTime + float32(p[i].InputTime)
						IPlist[k].AverageInputTime = IPlist[k].TotalTime / float32(IPlist[k].AuthCount) / 1000000

						IPlist[k].LongestTime = authInfo[j].InputTime
						IPlist[k].ShortestTime = authInfo[j].InputTime
						IPlist[k].Latitude = authInfo[j].Latitude
						IPlist[k].Longitude = authInfo[j].Longitude
						IPlist[k].Distance = authInfo[j].Distance
						break findIPlist
					}

				}

				fmt.Printf("\x1b[41m%s\x1b[0m\n", "-----Input of password------")
				fmt.Printf("\nPacket No.%d\n", i)
				fmt.Printf("Time: %s\n", p[i].PacketTime)
				fmt.Printf("Length: %d byte\n", p[i].Length)
				fmt.Printf("SSH Client: %s\n", p[i].SshClient)
				fmt.Printf("UsedCipher: %s\n\n", p[i].Cipher)
				// fmt.Println(packet)

				fmt.Printf("<SSH Authentication>\n\x1b[33m%s\x1b[0m ==>> %s\n", p[i].SrcIP, p[i].DstIP)

				// Show connection lacation.
				fmt.Printf("Country: %v\n", p[i].CountryName)
				fmt.Printf("Latitude: %v   Longitude: %v\n", p[i].Latitude, p[i].Longitude)
				fmt.Printf("Distance: %f km\n", authInfo[j].Distance)

				// Show authentication time.
				fmt.Printf("Auth Time: \x1b[31m%v\x1b[0m\n", p[i].AuthTime)
				fmt.Printf("Input Time: \x1b[31m%s\x1b[0m\n", p[i].InputTime)
				fmt.Printf("RTT:        %s\n", p[i].RTT)
				fmt.Printf("\x1b[41m%s\x1b[0m\n", "-----------------------------------------------------------")

				j = j + 1
			}
		}

		// If you want to display all packets, uncomment this.
		// }else{
		// 	fmt.Printf("Packet No.%d\n", i)
		// 	fmt.Println(packet)
		// 	info.SuccessAuth(packet, serverIP)
		// }

		// fmt.Print("============================================================================\n\n")
	}

	// JSONファイルに出力．
	json.JsonAuth(authInfo)
	json.OutputIPList(IPlist)
	json.CountryName(IPlist)

	end := time.Now()
	fmt.Printf("実行時間：%f秒\n", (end.Sub(start)).Seconds())
}

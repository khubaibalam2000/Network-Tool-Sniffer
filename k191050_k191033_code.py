import struct
import socket as s

def Ethernet_Frames(data):
    destination_mac, source_mac, ethernet_protocol = struct.unpack('! 6s 6s H', data[:14])
    formatted_dmac = Format_Mac(destination_mac)
    formatted_smac = Format_Mac(source_mac)
    return formatted_dmac, formatted_smac, s.htons(ethernet_protocol), data[14:]

def Format_Mac(unformatted_mac):
    ufmac = map('{:02x}'.format, unformatted_mac)
    fmac = ':'.join(ufmac)
    return fmac

def ipv4_datagram(data):
    vlen = data[0]
    version = vlen >> 4
    hlen = (vlen & 15) * 4
    time_to_leave, ip_protocol, source, destination = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, hlen, time_to_leave, ip_protocol, Ipv4_format(source), Ipv4_format(destination), data[hlen:]

def Ipv4_format(ip):
    fip = map(str, ip)
    fvip = '.'.join(fip)
    return fvip

def ICMP_segment(data):
    icmp_cat, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_cat, code, checksum, data[4:]

def TCP_segment(data):
    source_port, desitnation_port, seq_no, ack, flags = struct.unpack('! H H L L H', data[:14])
    offset = (flags >> 12) * 4
    flag_urg = (flags & 32) >> 5
    flag_ack = (flags & 16) >> 4
    flag_psh = (flags & 8) >> 3
    flag_rst = (flags & 4) >> 2
    flag_syn = (flags & 2) >> 1
    flag_fin = (flags & 1)
    return source_port, desitnation_port, seq_no, ack, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def UDP_segment(data):
    source_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return source_port, dest_port, size, data[8:]

if __name__ == '__main__':
    connection = s.socket(s.AF_PACKET, s.SOCK_RAW, s.ntohs(3))
    f = open("data.txt", "w")
    while 1:
        unprocessed_data, address = connection.recvfrom(65535)
        dmac, smac, ethernet_protocol, processed_data = Ethernet_Frames(unprocessed_data)
        print('Ethernet Frames: Destination: {}, Source: {}, Protocol: {}'.format(dmac, smac, ethernet_protocol))
        f.write('Ethernet Frames: Destination: {}, Source: {}, Protocol: {}\n'.format(dmac, smac, ethernet_protocol))
        f.close()
        f = open("data.txt", "a")
        if ethernet_protocol == 8:
            version, hlen, time_to_leave, ip_protocol, source, destination, processed_data = ipv4_datagram(processed_data)
            print("\tIPv4: Version: {}, Header length: {}, TTL: {}, IP Protocol: {}, Source: {}, Destination: {}, Data: ".format(version, hlen, time_to_leave, ip_protocol, source, destination, processed_data.decode('iso-8859-1')))
            f.write("\tIPv4: Version: {}, Header length: {}, TTL: {}, IP Protocol: {}, Source: {}, Destination: {}, Data: \n".format(version, hlen, time_to_leave, ip_protocol, source, destination, processed_data.decode('iso-8859-1')))
            if ip_protocol == 1:
                icmp_cat, code, checksum, processed_data = ICMP_segment(processed_data)
                print("\t\tICMP Category: {}, Code: {}, Checksum: {}, Data: {}".format(icmp_cat, code, checksum, processed_data.decode('iso-8859-1')))
                f.write("\t\tICMP Category: {}, Code: {}, Checksum: {}, Data: {}\n".format(icmp_cat, code, checksum, processed_data.decode('iso-8859-1')))
            elif ip_protocol == 6:
                source_port, desitnation_port, seq_no, ack, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, processed_data = TCP_segment(processed_data)
                print("\t\tTCP Source Port: {}, Destination Port: {}, Sequence Number: {}, Acknowledgement: {}, Offset: {}, Flag_Urg: {}, Flag_ACK: {}, Flag_psh: {}, Flag_Rst: {}, Flag_Syn: {}, Flag_fin: {} ".format(source_port, desitnation_port, seq_no, ack, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, processed_data.decode('iso-8859-1')))
                f.write("\t\tTCP Source Port: {}, Destination Port: {}, Sequence Number: {}, Acknowledgement: {}, Offset: {}, Flag_Urg: {}, Flag_ACK: {}, Flag_psh: {}, Flag_Rst: {}, Flag_Syn: {}, Flag_fin: {} \n".format(source_port, desitnation_port, seq_no, ack, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, processed_data.decode('iso-8859-1')))
                if(desitnation_port == 443):
                    print("\t\t\tHTTPS Packets")
                    f.write("\t\t\tHTTPS Packets\n")
                if(desitnation_port == 80):
                    print("\t\t\tHTTP Packets")
                    f.write("\t\t\tHTTP Packets\n")
                if(desitnation_port == 23):
                    print("\t\t\tTelnet Packets")
                    f.write("\t\t\tTelnet Packets\n")
                if(desitnation_port == 25):
                    print("\t\t\tSMTP Packets")
                    f.write("\t\t\tSMTP Packets\n")
                if(desitnation_port == 143 or desitnation_port == 993):
                    print("\t\t\tIMAP Packets")
                    f.write("\t\t\tIMAP Packets\n")

            elif ip_protocol == 17:
                source_port, dest_port, size, processed_data = UDP_segment(processed_data)
                print("\t\tUDP Source Port: {}, Destination Port: {}, Size: {}, Data: {}".format(source_port, dest_port, size, processed_data.decode('iso-8859-1')))
                f.write("\t\tUDP Source Port: {}, Destination Port: {}, Size: {}, Data: {}\n".format(source_port, dest_port, size, processed_data.decode('iso-8859-1')))
                if(dest_port == 53):
                    print("\t\t\tDNS Packets")
                    f.write("\t\t\tDNS Packets\n")

            else:
                print("Data: {}", processed_data.decode('iso-8859-1'))
                f.write("Data: {}\n", processed_data.decode('iso-8859-1'))

        else:
            print("Data: {}".format(processed_data.decode('iso-8859-1')))
            f.write("Data: {}\n".format(processed_data.decode('iso-8859-1')))

    f.close()

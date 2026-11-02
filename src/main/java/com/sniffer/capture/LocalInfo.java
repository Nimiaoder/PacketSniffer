package com.sniffer.capture;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.LinkLayerAddress;

import java.util.HashSet;
import java.util.Set;

/** 目前網卡的本機 IP / MAC，用來判斷封包是「接收」還是「送出」。 */
public record LocalInfo(Set<String> ips, Set<String> macs) {

    public static LocalInfo of(PcapNetworkInterface nif) {
        Set<String> ips = new HashSet<>();
        Set<String> macs = new HashSet<>();
        for (PcapAddress a : nif.getAddresses()) {
            if (a.getAddress() != null) ips.add(norm(a.getAddress().getHostAddress()));
        }
        for (LinkLayerAddress l : nif.getLinkLayerAddresses()) {
            macs.add(ByteArrays.toHexString(l.getAddress(), ":"));
        }
        return new LocalInfo(ips, macs);
    }

    public static String norm(String s) {
        if (s == null) return "";
        int i = s.indexOf('%');
        return (i >= 0 ? s.substring(0, i) : s).toLowerCase();
    }
}

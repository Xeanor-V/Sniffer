package main;

import gui.Devices;
import util.FileChooser;
import java.io.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.swing.JFileChooser;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.*;
import org.jnetpcap.protocol.tcpip.*;

public class Captura {
    
    static int ieee802;
    static int ethernet;
    static int mensaje_arp, paquete_ip;
    static int enc_tcp, enc_icmp, enc_udp, enc_desconocido;

    public static void globales (int n){
        ieee802 = 0;
        ethernet = 0;
        mensaje_arp = 0;
        paquete_ip = 0;
        enc_tcp = 0;
        enc_icmp = 0;
        enc_udp = 0;
        enc_desconocido = 0;
    }

    Devices frameDevices;
    Pcap pcap = null;
    List<PcapIf> alldevs = new ArrayList<>(); // Will be filled with NICs
    StringBuilder errbuf = new StringBuilder(); // For any error msgs
    JTextArea areaTXT;

    public Captura(JTextArea areaTXT, int type) {

        this.areaTXT = areaTXT;

        switch (type) {
            case 0:
                startOffline();
                break;
            case 1:
                getDevices();
                break;
        }

    }

    /* Obtiene las devices Al vuelo */
    public void getDevices() {
        try {
            List<String> nameDevs = new ArrayList<>();
            int r = Pcap.findAllDevs(alldevs, errbuf);
            if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
                System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
                return;
            }

            System.out.println("Network devices found:");

            int i = 0;
            for (PcapIf device : alldevs) {
                String description =
                        (device.getDescription() != null) ? device.getDescription()
                        : "No description available";
                final byte[] mac = device.getHardwareAddress();
                String dir_mac = (mac == null) ? "No tiene direccion MAC" : asString(mac);
                System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);
                nameDevs.add(description + " MAC:[" + dir_mac + "]");
                List<PcapAddr> direcciones = device.getAddresses();
                for (PcapAddr direccion : direcciones) {
                    System.out.println(direccion.getAddr().toString());
                }//foreach

            }//for

            frameDevices = new Devices(nameDevs, this);
            frameDevices.setVisible(true);

        } catch (IOException ie) {
            ie.printStackTrace();
        }

    }

    /* Metodo que se elige cuando se selecciona por archivo */
    public void startOffline() {

        redirectSystemStreams();
       // FileChooser chooser = new FileChooser();
        String fname = null;
       // fname = fname.replaceAll("\\\\", "/");
       // fname = chooser.getAbsolutePath();
        
        JFileChooser fileChooser = new JFileChooser(); 
        FileNameExtensionFilter extension = new FileNameExtensionFilter("archivos pcap (*.pcap)", "pcap");
        fileChooser.setFileFilter(extension);
        fileChooser.setDialogTitle("Abrir archivo");
        // set selected filter
        fileChooser.setFileFilter(extension);
        int resultado = fileChooser.showOpenDialog(null);
        File f = null;
        if(resultado==JFileChooser.APPROVE_OPTION){
            f = fileChooser.getSelectedFile();
            System.out.println("Archivo seleccionado: "+f.getAbsolutePath());
            fname = f.getName();
        }
        else
            return;
        pcap = Pcap.openOffline(fname, errbuf);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errbuf.toString());
            return;
        }

        /**
         * *************************************************************************
         * Fourth we enter the loop and tell it to capture 10 packets. The loop
         * method does a mapping of pcap.datalink() DLT value to JProtocol ID,
         * which is needed by JScanner. The scanner scans the packet buffer and
         * decodes the headers. The mapping is done automatically, although a
         * variation on the loop method exists that allows the programmer to
         * sepecify exactly which protocol ID to use as the data link type for
         * this pcap interface.
         * ************************************************************************
         */
        pcap.loop(-1, jpacketHandler, " ");
       

        /**
         * *************************************************************************
         * Last thing to do is close the pcap handle
         * ************************************************************************
         */
        pcap.close();
    }
    
    /* Termina de elegir el archivo */
    
    /* Selecciona los dispositivos de Al vuelo */
        public void startDevice(int deviceSelected) {
        
        redirectSystemStreams();
        PcapIf device = alldevs.get(deviceSelected); // We know we have atleast 1 device
        System.out
                .printf("\nChoosing '%s' on your behalf:\n",
                (device.getDescription() != null) ? device.getDescription()
                : device.getName());

        /**
         * *************************************************************************
         * Second we open up the selected device
         * ************************************************************************
         */
        /*"snaplen" is short for 'snapshot length', as it refers to the amount of actual data captured from each packet passing through the specified network interface.
         64*1024 = 65536 bytes; campo len en Ethernet(16 bits) tam máx de trama */
        int snaplen = 64 * 1024;           // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000;           // 10 seconds in millis


        pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }//if

        /**
         * ******F I L T R O*******
         */
        PcapBpfProgram filter = new PcapBpfProgram();
        String expression = ""; // "port 80";
        int optimize = 0; // 1 means true, 0 means false
        int netmask = 0;
        int r2 = pcap.compile(filter, expression, optimize, netmask);
        if (r2 != Pcap.OK) {
            System.out.println("Filter error: " + pcap.getErr());
        }//if
        pcap.setFilter(filter);

        /**
         * *************************************************************************
         * Fourth we enter the loop and tell it to capture 10 packets. The loop
         * method does a mapping of pcap.datalink() DLT value to JProtocol ID,
         * which is needed by JScanner. The scanner scans the packet buffer and
         * decodes the headers. The mapping is done automatically, although a
         * variation on the loop method exists that allows the programmer to
         * sepecify exactly which protocol ID to use as the data link type for
         * this pcap interface.
         * ************************************************************************
         */
        pcap.loop(10, jpacketHandler, " ");
         System.out.println("De los 10 capturas " + ethernet + " son ethernet802 y "+ ieee802 +" son ieee" );

        /**
         * *************************************************************************
         * Last thing to do is close the pcap handle
         * ************************************************************************
         */
        pcap.close();
    }
    /* Termina de seleccionar al vuelo */
        
    /* Implementacion de TODAS las Tramas */
    PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
        public void nextPacket(PcapPacket packet, String user) {

            System.out.printf("\n\nPaquete recibido el %s caplen=%-4d longitud=%-4d %s\n\n",
                    new Date(packet.getCaptureHeader().timestampInMillis()),
                    packet.getCaptureHeader().caplen(), // Length actually captured
                    packet.getCaptureHeader().wirelen(), // Original length
                    user // User supplied object
                    );

            /**
             * ****Desencapsulado*******
             */
            for (int i = 0; i < packet.size(); i++) {
                System.out.printf("%02X ", packet.getUByte(i));

                if (i % 16 == 15) {
                    System.out.println("");
                }
            }//if

            int longitud = (packet.getUByte(12) * 256) + packet.getUByte(13);
            System.out.printf("\nLongitud: %d (%04X)", longitud, longitud);
            if (longitud < 1500) {
                System.out.println("--->Trama IEEE802.3");
                System.out.printf(" |-->MAC Destino: %02X:%02X:%02X:%02X:%02X:%02X", packet.getUByte(0), packet.getUByte(1), packet.getUByte(2), packet.getUByte(3), packet.getUByte(4), packet.getUByte(5));
                System.out.printf("\n |-->MAC Origen: %02X:%02X:%02X:%02X:%02X:%02X", packet.getUByte(6), packet.getUByte(7), packet.getUByte(8), packet.getUByte(9), packet.getUByte(10), packet.getUByte(11));
                System.out.printf("\n |-->DSAP: %02X", packet.getUByte(14));
                //System.out.println(packet.getUByte(15)& 0x00000001);
                int ssap = packet.getUByte(15) & 0x00000001;
                String c_r = (ssap == 1) ? "Respuesta" : (ssap == 0) ? "Comando" : "Otro";
                System.out.printf("\n |-->SSAP: %02X   %s", packet.getUByte(15), c_r);

                String Ns = "";
                String Nr = "";
                String PF = "";
                String dosbin = "";
                String unobin = "";
                String tipotrama = "";

                if (longitud > 3) {
                    int uno = packet.getUByte(16);
                    unobin = Integer.toBinaryString(uno);
                    while (unobin.length() < 8) {
                        unobin = "0" + unobin;
                    }
                    int dos = packet.getUByte(17);
                    dosbin = Integer.toBinaryString(dos);
                    while (dosbin.length() < 8) {
                        dosbin = "0" + dosbin;
                    }
                    unobin = new StringBuilder(unobin).reverse().toString();
                    dosbin = new StringBuilder(dosbin).reverse().toString();
                    System.out.println("\n\nCampo de control (en binario): " + unobin + dosbin);
                    if (unobin.charAt(0) == '0') {
                        tipotrama = "I";
                        System.out.println("Tipo de Trama: " + tipotrama);
                        for (int i = 1; i < 8; i++) {
                            Ns += unobin.charAt(i);
                        }
                        for (int i = 1; i < 8; i++) {
                            Nr += dosbin.charAt(i);
                        }
                        System.out.println("Ns: " + Integer.parseInt(new StringBuilder(Ns).reverse().toString(), 2));
                        System.out.println("Nr: " + Integer.parseInt(new StringBuilder(Nr).reverse().toString(), 2));

                        switch (dosbin.charAt(0)) {
                            case '1':
                                if (ssap == 0) {
                                    PF = "P";
                                } else {
                                    PF = "F";
                                }
                                break;
                            default:
                                PF = "--";

                        }
                        System.out.println("P/F: " + PF);
                    }
                    if (unobin.charAt(0) == '1' && unobin.charAt(1) == '0') {
                        tipotrama = "S(";
                        switch (unobin.charAt(2)) {
                            case '0':
                                if (unobin.charAt(3) == '0') {
                                    tipotrama += "RR)";
                                } else {
                                    tipotrama += "REJ";
                                }
                                break;
                            case '1':
                                if (unobin.charAt(3) == '0') {
                                    tipotrama += "RNR)";
                                } else {
                                    tipotrama += "SREJ)";
                                }
                                break;
                        }
                        for (int i = 1; i < 8; i++) {
                            Nr += dosbin.charAt(i);
                        }
                        System.out.println("Tipo de Trama: " + tipotrama);
                        System.out.println("Ns: --");
                        System.out.println("Nr: " + Integer.parseInt(new StringBuilder(Nr).reverse().toString(), 2));

                        switch (dosbin.charAt(0)) {
                            case '1':
                                if (ssap == 0) {
                                    PF = "P";
                                } else {
                                    PF = "F";
                                }
                                break;
                            default:
                                PF = "--";

                        }
                        System.out.println("P/F: " + PF);
                    }
                    if (unobin.charAt(0) == '1' && unobin.charAt(1) == '1') {
                        tramaunsigned(unobin, ssap);
                    }
                } else {
                    int uno = packet.getUByte(16);
                    unobin = Integer.toBinaryString(uno);
                    while (unobin.length() < 8) {
                        unobin = "0" + unobin;
                    }
                    unobin = new StringBuilder(unobin).reverse().toString();
                    System.out.println("\n\nCampo de control (en binario): " + unobin);
                    if (unobin.charAt(0) == '0') {
                        tipotrama = "I";
                        System.out.println("Tipo de Trama: " + tipotrama);
                        for (int i = 1; i < 4; i++) {
                            Ns += unobin.charAt(i);
                        }
                        for (int i = 5; i <= 8; i++) {
                            Nr += unobin.charAt(i);
                        }
                        System.out.println("Ns: " + Integer.parseInt(new StringBuilder(Ns).reverse().toString(), 2));
                        System.out.println("Nr: " + Integer.parseInt(new StringBuilder(Nr).reverse().toString(), 2));

                        switch (unobin.charAt(4)) {
                            case '1':
                                if (ssap == 0) {
                                    PF = "P";
                                } else {
                                    PF = "F";
                                }
                                break;
                            default:
                                PF = "--";

                        }
                        System.out.println("P/F: " + PF);
                    }
                    if (unobin.charAt(0) == '1' && unobin.charAt(1) == '0') {
                        tipotrama = "S(";
                        switch (unobin.charAt(2)) {
                            case '0':
                                if (unobin.charAt(3) == '0') {
                                    tipotrama += "RR)";
                                } else {
                                    tipotrama += "REJ";
                                }
                                break;
                            case '1':
                                if (unobin.charAt(3) == '0') {
                                    tipotrama += "RNR)";
                                } else {
                                    tipotrama += "SREJ)";
                                }
                                break;
                        }
                        for (int i = 5; i <= 8; i++) {
                            Nr += unobin.charAt(i);
                        }
                        System.out.println("Tipo de Trama: " + tipotrama);
                        System.out.println("Ns: --");
                        System.out.println("Nr: " + Integer.parseInt(new StringBuilder(Nr).reverse().toString(), 2));

                        switch (unobin.charAt(4)) {
                            case '1':
                                if (ssap == 0) {
                                    PF = "P";
                                } else {
                                    PF = "F";
                                }
                                break;
                            default:
                                PF = "--";

                        }
                        System.out.println("P/F: " + PF);
                    }
                    if (unobin.charAt(0) == '1' && unobin.charAt(1) == '1') {
                        tramaunsigned(unobin, ssap);
                    }
                }

            } else if (longitud >= 1500) {
                Ethernet eth = new Ethernet();
                if (packet.hasHeader(eth)) {
                    longitud = eth.getUShort(12);
                    System.out.printf("Longitud:::%X", longitud);
                    //JBuffer buffer = eth;
                    int tipo = eth.type();
                    //System.out.println("Tipo:"+tipo);
                    System.out.printf("Tipo=%X\n", tipo);
                    switch (tipo) {
                        case (int) 2054:
                            System.out.println("Mensaje ARP");
                            Arp arp = new Arp();
                            if (packet.hasHeader(arp)) {
                                int operacion = arp.operation();
                                int[] sp = new int[4];
                                int[] tp = new int[4];
                                sp[1] = ((arp.spa()[1]) < 0) ? (arp.spa()[1]) + 256 : arp.spa()[1];
                                sp[2] = ((arp.spa()[2]) < 0) ? (arp.spa()[2]) + 256 : arp.spa()[2];
                                sp[3] = ((arp.spa()[3]) < 0) ? (arp.spa()[3]) + 256 : arp.spa()[3];
                                tp[0] = ((arp.tpa()[0]) < 0) ? (arp.tpa()[0]) + 256 : arp.tpa()[0];
                                tp[1] = ((arp.tpa()[1]) < 0) ? (arp.tpa()[1]) + 256 : arp.tpa()[1];
                                tp[2] = ((arp.tpa()[2]) < 0) ? (arp.tpa()[2]) + 256 : arp.tpa()[2];
                                               sp[0] = ((arp.spa()[0]) < 0) ? (arp.spa()[0]) + 256 : arp.spa()[0];
                 tp[3] = ((arp.tpa()[3]) < 0) ? (arp.tpa()[3]) + 256 : arp.tpa()[3];
                                String MACO = "", MACD = "", aux2 = "";
                                for (int i = 0; i < arp.sha().length; i++) {
                                    int aux = ((arp.sha()[i]) < 0) ? (arp.sha()[i]) + 256 : arp.sha()[i];
                                    aux2 = Integer.toHexString(aux);
                                    if (aux2.length() < 2) {
                                        aux2 = "0" + aux2;
                                    }
                                    MACO += aux2;
                                    if (i != 5) {
                                        MACO += ":";
                                    }
                                }
                                for (int i = 0; i < arp.tha().length; i++) {
                                    int aux = ((arp.tha()[i]) < 0) ? (arp.tha()[i]) + 256 : arp.tha()[i];
                                    aux2 = Integer.toHexString(aux);
                                    if (aux2.length() < 2) {
                                        aux2 = "0" + aux2;
                                    }
                                    MACD += aux2;
                                    if (i != 5) {
                                        MACD += ":";
                                    }
                                }

                                System.out.println("\nSHA: " + MACO + " THA: " + MACD + "\n");
                                if (operacion == 1) {
                                    if (sp.equals(tp)) {
                                        System.out.println("ARP gratuito direccion " + sp[0] + "." + sp[1] + "." + sp[2] + "." + sp[3]);
                                    } else {
                                        System.out.println("Consulta ARP Quien tiene la direccion " + tp[0] + "." + tp[1] + "." + tp[2] + "." + tp[3] + "??");
                                    }//else
                                } else if (operacion == 2) {
                                    System.out.println("Respuesta ARP " + sp[0] + "." + sp[1] + "." + sp[2] + "." + sp[3] + " es" + asString(arp.sha()));
                                }//if
                            }//if
                            break;
                        case (int) 2048:
                            System.out.println("Paquete IP");
                            Ip4 ip = new Ip4();
                            if (packet.hasHeader(ip)) {
                                int s1 = ((ip.source()[0]) < 0) ? (ip.source()[0]) + 256 : ip.source()[0];
                                int s2 = ((ip.source()[1]) < 0) ? (ip.source()[1]) + 256 : ip.source()[1];
                                int s3 = ((ip.source()[2]) < 0) ? (ip.source()[2]) + 256 : ip.source()[2];
                                int s4 = ((ip.source()[3]) < 0) ? (ip.source()[3]) + 256 : ip.source()[3];
                                int d1 = ((ip.destination()[0]) < 0) ? (ip.destination()[0]) + 256 : ip.destination()[0];
                                int d2 = ((ip.destination()[1]) < 0) ? (ip.destination()[1]) + 256 : ip.destination()[1];
                                int d3 = ((ip.destination()[2]) < 0) ? (ip.destination()[2]) + 256 : ip.destination()[2];
                                int d4 = ((ip.destination()[3]) < 0) ? (ip.destination()[3]) + 256 : ip.destination()[3];

                                System.out.println("IP destino: " + d1 + "." + d2 + "." + d3 + "." + d4);
                                System.out.println("IP origen: " + s1 + "." + s2 + "." + s3 + "." + s4);
                                int protocolo = ip.type();
                                System.out.println("Protocolo" + protocolo + " Descripcion:" + ip.typeDescription());
                                //System.out.println("Protocolo_d"+ip.typeDescription());
                                switch (protocolo) {
                                    case 6:
                                        Tcp tcp = new Tcp();
                                        if(packet.hasHeader(tcp)){
                                            System.out.println("\nENCABEZADO TCP");
                                            System.out.println("\n Puerto Origen: ");
                                            System.out.println("" + tcp.source());
                                            System.out.println("\n Puerto Destino: ");
                                            System.out.println("" + tcp.destination());
                                            System.out.println("\n Numero de sequencia: ");
                                            System.out.printf("%02X ",tcp.seq());
                                            System.out.println("(" + tcp.seq() + ")");
                                            System.out.println("\n Numero de acuse: ");
                                            System.out.printf("%02X ",tcp.ack());
                                            System.out.println("(" + tcp.ack() + ")");
                                            System.out.println("\n Offset: ");
                                            System.out.println("" + tcp.hlen());
                                            System.out.println("\n Reservado: ");
                                            System.out.println("" + tcp.reserved());
                                            System.out.println("\n Flags: ");
                                            System.out.println("Estado - Descripcion");
                                            System.out.println(tcp.flags_CWR() + " - CWR");
                                            System.out.println(tcp.flags_ECE() + " - ECN Echo (ECE)");
                                            System.out.println(tcp.flags_URG() + " - Urgente URG");
                                            System.out.println(tcp.flags_ACK() + " - Acuse ACK");
                                            System.out.println(tcp.flags_PSH() + " - Push");
                                            System.out.println(tcp.flags_RST() + " - Reset");
                                            System.out.println(tcp.flags_SYN() + " - Synchronize");
                                            System.out.println(tcp.flags_FIN() + " - FIN");
                                            System.out.println("\n Ventana: ");
                                            System.out.println("" + tcp.window());
                                            System.out.println("\n Checksum: ");
                                            System.out.printf("%02X ",tcp.calculateChecksum());
                                            System.out.println("(" + tcp.calculateChecksum() + ")");
                                            System.out.println("\n Urgent Point: ");
                                            System.out.println("" + tcp.urgent());
                                        }
                                        break;
                                    case 1:
                                            Icmp icmp = new Icmp();
                                        if(packet.hasHeader(icmp)){
                                            System.out.println("\nENCABEZADO ICMP");
                                            System.out.println("\n Tipo : ");
                                            System.out.println("" + icmp.type());
                                            System.out.println("\n Codigo : ");
                                            System.out.println("" + icmp.code());
                                            System.out.println("\n Descripcion : ");
                                            System.out.println("" + icmp.typeDescription());
                                            System.out.println("\n Checksum : ");
                                            System.out.printf("%02X ",icmp.checksum());
                                            System.out.println("(" + icmp.checksum() + ")");
                                        }//if
                                        break;
                                    case 17:
                                        Udp udp = new Udp();
                                        if(packet.hasHeader(udp)){
                                            System.out.println("\n ENCABEZADO UDP");
                                            System.out.println("\n Puerto Origen: ");
                                            System.out.println("" + udp.source());
                                            System.out.println("\n Puerto Destino: ");
                                            System.out.println("" + udp.destination());
                                            System.out.println("\n Longitud: ");
                                            System.out.println("" + udp.length());
                                            System.out.println("\n Checksum: ");
                                            System.out.printf("%02X ",udp.calculateChecksum());
                                            System.out.println("(" + udp.calculateChecksum() + ")");
                                        }
                                        break;
                                    default:
                                }//switch_protocolo                                                
                            }//if_ip
                            break;
                        default:
                            break;
                    }//switch
                }
            }//else
            //System.out.println("\n\nEncabezado: "+ packet.toHexdump());
        }
    };

    private static String asString(final byte[] mac) {
        final StringBuilder buf = new StringBuilder();
        for (byte b : mac) {
            if (buf.length() != 0) {
                buf.append(':');
            }
            if (b >= 0 && b < 16) {
                buf.append('0');
            }
            buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
        }

        return buf.toString();
    }

    public static void tramaunsigned(String unobin, int ssap) {
        String PF = "";
        String codigo = "";
        String tipotrama = "U(";

        codigo += "" + unobin.charAt(2) + unobin.charAt(3) + unobin.charAt(5) + unobin.charAt(6) + unobin.charAt(7);
        System.out.println("Codigo: " + codigo);
        int codigoint = Integer.parseInt(codigo, 2);
        switch (codigoint) {
            case 1:
                tipotrama += "SNRM)";
                break;
            case 27:
                tipotrama += "SNRME)";
                break;
            case 24:
                tipotrama += "SARM,DM)";
                break;
            case 26:
                tipotrama += "SARME)";
                break;
            case 28:
                tipotrama += "SABM)";
                break;
            case 30:
                tipotrama += "SABME)";
                break;
            case 0:
                tipotrama += "UI)";
                break;
            case 6:
                tipotrama += "UA)";
                break;
            case 2:
                tipotrama += "DISC,RD)";
                break;
            case 25:
                tipotrama += "RSET)";
                break;
            case 29:
                tipotrama += "XID)";
                break;
        }

        System.out.println("Tipo de Trama: " + tipotrama);
        System.out.println("Ns: --");
        System.out.println("Nr: --");
        switch (unobin.charAt(4)) {
            case '1':
                if (ssap == 0) {
                    PF = "P";
                } else {
                    PF = "F";
                }
                break;
            default:
                PF = "--";
        }
        System.out.println("P/F: " + PF);
    }
/*Termina implementacion de TODAS las tramas*/

    
    private void updateTextArea(final String text) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                areaTXT.append(text);
            }
        });
    
    }
    private void redirectSystemStreams() {
        OutputStream out = new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                updateTextArea(String.valueOf((char) b));
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                updateTextArea(new String(b, off, len));
            }

            @Override
            public void write(byte[] b) throws IOException {
                write(b, 0, b.length);
            }
        };

        System.setOut(new PrintStream(out, true));
        System.setErr(new PrintStream(out, true));
    }
}
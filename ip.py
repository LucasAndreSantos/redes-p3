#libs

from iputils import *
from socket import IPPROTO_ICMP, IPPROTO_TCP
from ipaddress import ip_address, ip_network
import struct
from tcputils import str2addr



class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """ 
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.idenficador = 0
        self.id = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            # TODO: Trate corretamente o campo TTL do datagrama
            prox_hop = self._next_hop(dst_addr)
            ttl = ttl - 1
            proto = IPPROTO_TCP
            if (ttl == 0):
                proto = IPPROTO_ICMP  
                checksum = calc_checksum(struct.pack('!BBHI', 11, 0, 0, 0) + datagrama[:28])
                msg = struct.pack('!BBHI', 11, 0, checksum, 0) + datagrama[:28]              
                correct_datagrama = struct.pack('!BBHHHBBH', 69, 0, 20+len(msg), identification, flags+frag_offset, 64, proto, 0) + str2addr(self.meu_endereco) + str2addr(src_addr)
                checksum = calc_checksum(correct_datagrama)
                datagrama = struct.pack('!BBHHHBBH', 69, 0, 20+len(msg), identification, flags+frag_offset, 64, proto, checksum) + str2addr(self.meu_endereco) + str2addr(src_addr) + msg
                prox_hop = self._next_hop(self.meu_endereco)
            else:
                correct_datagrama = struct.pack('!BBHHHBBH', 69, 0, 20+len(payload), identification, flags+frag_offset, ttl, proto, 0) + str2addr(src_addr) + str2addr(dst_addr)
                checksum = calc_checksum(correct_datagrama)
                datagrama = struct.pack('!BBHHHBBH', 69, 0, 20+len(payload), identification, flags+frag_offset, ttl, proto, checksum) + str2addr(src_addr) + str2addr(dst_addr) + payload
            self.enlace.enviar(datagrama, prox_hop)
            

    def _next_hop(self, dest_addr):
        prox_hop = None
        n_maior = 0
        ip_destino = ip_address(dest_addr)
        for v in self.tabela:
            ip = ip_network(v[0])
            n_corrente = int(v[0].split('/')[1])
            if (ip_destino in ip and n_corrente >= n_maior):
                prox_hop = v[1]
                n_maior = n_corrente
        return prox_hop

        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.


    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela = tabela
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        prox_hop = self._next_hop(dest_addr)
        vihl, dscpecn, tam_total, identification, flagsfrag, ttl, protocolo, checksum, src_addr = 69, 0, 20+len(segmento), self.id, 0, 64, 6, 0, self.meu_endereco
        correct_datagrama = struct.pack('!BBHHHBBH', vihl, dscpecn, tam_total, identification, flagsfrag, ttl, protocolo, checksum) + str2addr(src_addr) + str2addr(dest_addr)
        checksum = calc_checksum(correct_datagrama)
        datagrama = struct.pack('!BBHHHBBH', vihl, dscpecn, tam_total, identification, flagsfrag, ttl, protocolo, checksum) + str2addr(src_addr) + str2addr(dest_addr) + segmento
        #TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        #datagrama com o cabeçalho IP, contendo como payload o segmento.
        self.enlace.enviar(datagrama, prox_hop)

/*############################################################
##############################################################
#                                                            #
#           Frag - Emissor de Pacotes Fragmentados ICMP      #
#                    Sender of Frags ICMP Packets            #
#                    GPL - General Public License            #
#                            -- ## --                        #
#                       Name: fragicmp - v0.2                #
#                          Autor: Khun                       #
#                       Date:   20/05/2008                   #
#                                                            #
#             Felipe Ecker (Khun) - khun@hexcodes.org        #
#                                                            #
#############################################################*/

//                            Fragicmp:
// 
// Envia um datagrama ICMP tipo 8 (Echo Request) fragmentado em quatro pacotes.
// No 1o Pacote existe o envio do 1o fragmento com Header Ip + 
// Header icmp + 8 bytes de payload de dados c/ Char "A" (flag MF e offsset Zero).
//
// No 2o Fragmento vem envio o header Ip + 16 bytes de payload de dados c/ char "B". 
// (flag MF e offsset 2).
// Offset 2 ==> Acrescentar os dados a partir do segundo octeto no buffer. 
// O 1o octeto contem o char "A" do primeiro fragmento.
//
// No 3o Fragmento vem o envio do Header IP + 8 bytes de payload de dados c/ char "D". 
// (Flag MF e offset 4)
// OffSet 4 ==> Acrescentar os dados a partir do quarto octeto no Buffer. 
// O 2o  e o 3o Octeto contem o char "B" (16 bytes dados) enviado no 2o Fragmento.
//
// Com isso, embora o buffer ja esteja completo, a flag MF diz a pilha TCP/IP
// do Sistema que ainda restam fragmentos e aguarda por mais.
//
// No 4o Fragmento vem o envio do Header Ip + 8 bytes de payload de dados c/ char "C". 
// (Flag MF zerada offset 4)
// Offset 4 ==> Aqui o Overlaping c/ ultimo fragmento (MF= 0x0004). 
// Eu sobreescrevo a area de dados enviado anteriormente no fragmento 3 (CHAR "C"), 
// e aqui vem o envio do payload de dados com char "D" mirando o offset 0x0004, 
// que por sua vez "sobrescreve" essa area que anteriormente continha "C". 
// O Overwrite acontece na recepcao do pacote que sera montado pelo Kernel.
//
//###########################################################

#include <stdio.h>     
#include <stdlib.h>  
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>  
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>  
#include <linux/if.h>  

#define ERR   -1

// Globais
int io; 


// CheckSum Global 
u_short in_cksum(u_short *addr, int len) {

  register int nleft  = len;
  register u_short *w = addr;
  register int sum  = 0;
  u_short answer   = 0;

  while (nleft > 1)  {
    sum  += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    *(u_char *)(&answer) = *(u_char *)w ;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return(answer);
}


// meu_ip()
char *meu_ip(const char *placa) {

  int meu_sock;
  struct ifreq e;
  char *ip;

  meu_sock = socket(AF_INET, SOCK_DGRAM, 0);
  e.ifr_addr.sa_family = AF_INET;
  strncpy(e.ifr_name, placa, IFNAMSIZ-1);
  io= ioctl(meu_sock, SIOCGIFADDR, &e);
  close(meu_sock);
  ip= (char *) inet_ntoa(((struct sockaddr_in *)&e.ifr_addr)->sin_addr);
  return ip;
}


//   Aqui tem inicio Main()
//   Alguns Sistemas Operacionais como o MSWINDOWS tem uma
//   política (algoritmo) de remontagem de fragmentos chamada de 
//   "Fragmentation Policy First", onde o algorítmo de reassembly
//   de fragmentos favorece o fragmento original do datagrama, sendo
//   que qualquer fragmento com Offset ja enviado nao sera sobrescrito.
//   
//   Sem o Overlaping, ou seja, nao aceitara sobreposicao de fragmentos.
//   Com isso, Win32 xp ou win2k3 podem nao responder ao echo request
//   por nao remontar o 4o fragmento com overlaping, acusando cksum error, 
//   ou alerta de Overlap
//
//   Altere o tamanho do buffer "dados" e mude o offset do quarto
//   fragmento de 0x4 para 0x5. Assim nao havera Overlap e a pilha do Sistema
//   MsWindows passa a processar o pacote echo request.
//
//   *NIX se comportam normalmente. BSD systems tambem.


int main(int argc, char *argv[]) {

  char *origem, *destino="", *end_ip;
  unsigned char  *dados, *recvbuff;
  struct icmphdr *icmp;
  struct iphdr *ip;
  struct sockaddr_in home, alvo, remoto;
  struct hostent *host;
  struct timeval tim;
  fd_set redfs;
  static char opcoes[] = "s:d:";
  int mysock, opt, sockicmp, n, i, E, sel, setsock= 1;
  unsigned int tamrem;

  if ((argc < 3) || (argc > 5)) {   
    fprintf(stderr,"\nUse: \n%s -d (Destino)\n", argv[0]);
    fprintf(stderr,"%s -s (Origem) -d (Destino) \t\t - Opcao \"-s\" opcional [spoof].\n\n", argv[0]);
    exit(1);
  }

  origem= NULL;
  while((opt = getopt(argc,argv,opcoes)) != -1) {
    switch(opt) {
      case 'd':
        destino= (char *) optarg;
        break;
      case 's':
        origem= (char *) optarg;
        break;
      default:
        fprintf(stderr,"Opcao Invalida!\n");
        exit(-1);
    }
  }

  if(!origem) {
    end_ip= meu_ip("eth0");
  if (!(io)) 
    { origem= end_ip; goto P; }
  end_ip= meu_ip("eth1");
  if (!(io)) 
    { origem= end_ip; goto P; }
  end_ip= meu_ip("eth2");
  if (!(io)) 
    { origem= end_ip; goto P; }
  end_ip= meu_ip("eth3");
  if (!(io)) 
    { origem= end_ip; goto P; }
  end_ip= meu_ip("eth4");
  if (!(io)) 
    { origem= end_ip; goto P; }
  fprintf(stderr,"\nSem Interfaces de Rede definida, Use -s \n\n");
     exit(-1);
  }

P: 
  srand(time(NULL)); 
  mysock= socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  sockicmp= socket(AF_INET, SOCK_RAW, 1);

  if (mysock < 0) { perror("\nFalha ao Criar o Socket IPPROTO_RAW !!\n");  exit(ERR); }
  if (sockicmp < 0) { perror("\nFalha ao Criar o Socket IPPROTO_ICMP !!\n");  exit(ERR); }
  setsockopt(mysock, IPPROTO_IP, IP_HDRINCL, (char *) &setsock, sizeof(setsock));
  
  alvo.sin_family= AF_INET;
  if ((host= (struct hostent *) gethostbyname(destino)) == NULL) {
  herror("Erro em Hostname de Destino -- Dest Failure"); 
  close(mysock); close(sockicmp); exit(ERR); 
  } 

  bcopy(host->h_addr_list[0], &(alvo.sin_addr.s_addr),host->h_length); 
  for (i= 0; i < 8; i++) alvo.sin_zero[i]= '\0';

  home.sin_family= AF_INET;
  home.sin_addr.s_addr= inet_addr(origem);
  for (i= 0; i < 8; i++) home.sin_zero[i]= '\0';
  
  dados= (unsigned char *) calloc(1, 60); // Aloca 1 buffer com 60 bytes, inicializa com 0'
  if (!dados) { 
    fprintf(stderr,"\nImpossivel alocar memoria!\n\n"); 
    close(sockicmp); close(mysock); exit(-1); 
  }

  ip= (struct iphdr *) dados;
  icmp= (struct icmphdr *) (dados + sizeof(struct iphdr));   
  
  ip->saddr = home.sin_addr.s_addr;    // Ip Origem
  ip->daddr = alvo.sin_addr.s_addr;    // Ip Destino
  ip->version = (20 / 5);              // Versao proto IP "4"
  ip->frag_off= htons(0x2000);         // flag MF, e offsset 0x000
  ip->ihl = 5;                         // tam. cabecalho Ip= 5 Octetos
  ip->ttl = 0x80;                      // TTL 0x80
  ip->id = rand() % 0xffff;            // ID ranomico entre 0 e 0xFFFF
  ip->protocol = 1;                    // Proto 1 (icmp)
  ip->tot_len = htons(0x24);           // Tam total do 1o Fragmento
  ip->check = in_cksum((u_short *)ip, sizeof(struct iphdr));
   
  icmp->type             =  0x08;      //Echo Request
  icmp->code             =  0;    
  icmp->checksum         =  0;
  icmp->un.echo.id       =  rand() % 0xFF;// Id randomico entre 0x0 e 0xFF
  icmp->un.echo.sequence =  htons (1);    // Sequencia echo 1
    
  for(i=28; i <= 35; i++)             //Define o buffer de dados com char A 
          
  //(header ip (20 bytes) +
  dados[i]= 'A'; // header Icmp(8 bytes) + dados (8 bytes) = Total Envio no 1o Fragmento 36 Bytes.

  for (i=36; i<= 51; i++)  // Aqui nos precisamos definir o paylod
    dados[i]= 'B';         // com certa antecedencia. O checksum
  for (i=52; i<= 59; i++)  // precisa ser calculado antes do envio
    dados[i]= 'C';         // do 1o Fragmento, pois o buffer recebe
  for (i=52; i<= 59; i++)  // campo antes. Logo, precisamos calcular
    dados[i]= 'D';         // o cksum do datagrama inteiro antes de sendto
   
  fprintf(stderr,"Enviando Fragmento ICMP 1 - Host [%s]...\n", inet_ntoa(alvo.sin_addr));
  icmp->checksum= in_cksum((u_short *) icmp, ((sizeof(struct icmphdr))+ 32));
  E = sendto(mysock, dados, 0x24, 0,(struct sockaddr *) &alvo, sizeof(alvo));
  if (E == ERR) { 
    fprintf(stderr,"/nErro em Send\n\n"); 
    close(mysock); close(sockicmp); free(dados); exit(-1); 
  }
  else fprintf(stderr,"Ok...\n\n");

  sleep(1);

  //=========================================================//

  for(i=20; i <= 35; i++)   //Define o Buffer do 2o Fragmento com char B
    dados[i]= 'B';        //Header Ip (20 Bytes) + dados (16 bytes)= Total Envio 36 Bytes no 2o Fragmento 

  ip->frag_off = htons(0x2 | 0x2000); //Inserir no segundo octeto do Buffer
  ip->tot_len = htons(0x24); 
  ip->check = in_cksum((u_short *)ip, sizeof(struct iphdr));
  fprintf(stderr,"Enviando Fragmento ICMP 2 - Host [%s]...\n", inet_ntoa(alvo.sin_addr));
  E= sendto(mysock, dados, 0x24, 0,(struct sockaddr *) &alvo, sizeof(alvo));
  if (E == ERR) { 
    fprintf(stderr,"/nErro em Send/n/n"); 
    close(mysock); close(sockicmp); free(dados); exit(-1); 
  }
  else fprintf(stderr,"Ok...\n\n");

  sleep(1);
   
  //=============================================================//
   
  for(i=20; i <= 27; i++)//Define o Buffer do 3o Fragmento com char C
      dados[i]= 'C';     //Header Ip (20 Bytes) + dados (8 bytes)= Total Envio 28 Bytes no 3o Fragmento

  ip->frag_off = htons(0x4 | 0x2000); //Inserir no quarto octeto do buffer
  ip->tot_len = htons(0x1c);
  ip->check = in_cksum((u_short *)ip, sizeof(struct iphdr));
  fprintf(stderr,"Enviando Fragmento ICMP 3 - Host [%s]...\n", inet_ntoa(alvo.sin_addr));
  E= sendto(mysock, dados, 0x1c, 0,(struct sockaddr *) &alvo, sizeof(alvo));
  if (E == ERR) { 
     fprintf(stderr,"/nErro em Send/n/n"); 
     close(sockicmp); close(mysock); free(dados); exit(-1); 
  }
  else fprintf(stderr,"Ok...\n\n");

  sleep(1);

  //===============================================================//

  for(i=20; i <= 27; i++)//Define o Buffer do 4o Fragmento com char D
     dados[i]= 'D';      //Header Ip (20 Bytes) + dados (8 bytes)= Total Envio 28 Bytes no 4o Fragmento

  ip->frag_off = htons(0x4 | 0x0000);  // Inserir no 4o Octeto do Buffer (MF desligada= 0x0000)
  ip->tot_len = htons(0x1c);  
  ip->check = in_cksum((u_short *)ip, sizeof(struct iphdr));
  fprintf(stderr,"Enviando Fragmento ICMP 4 - Host [%s]...\n", inet_ntoa(alvo.sin_addr));
  E= sendto(mysock, dados, 0x1c, 0,(struct sockaddr *) &alvo, sizeof(alvo));
  if (E == ERR) { 
    fprintf(stderr,"/nErro em Send/n/n"); 
    close(sockicmp); close(mysock); free(dados); exit(-1); 
  }
  else fprintf(stderr,"Ok...\n\n");

  //===============================================================//
   
  tim.tv_sec= 4;  //timeout 4 segundos...
  tim.tv_usec= 0; // Microsegundos...
  FD_ZERO(&redfs);
  FD_SET(sockicmp, &redfs);
  sel= select(sockicmp + 1, &redfs, NULL, NULL, &tim);
  if (!sel) {
    fprintf(stderr,"TimeOut...\n\n");
    return 1;
  }
  
  recvbuff = (unsigned char*) calloc(1, 0x38);   // memset(recvbuff,0,0x38) - buffer para recebimento
  if (!recvbuff) { 
    fprintf(stderr,"\nImpossivel alocar Memoria!\n\n"); 
    close(sockicmp); close(mysock); exit(-1); 
  }

  ip= (struct iphdr *) recvbuff;
  icmp= (struct icmphdr *) (recvbuff + sizeof(struct iphdr));
  tamrem = sizeof(struct sockaddr_in);
  
  do {  
    n= recvfrom(sockicmp, recvbuff, 0x38, 0, (struct sockaddr *) &remoto, &tamrem);  
    if (n == ERR) fprintf(stderr, "\n\nErro em Recebimento de dados Reply.\n\n");
    }
  while(alvo.sin_addr.s_addr != remoto.sin_addr.s_addr);  

  fprintf(stderr,"Host [%s] responde c/ Echo Reply e %d Bytes de Dados - TTL [%d]\n\n", inet_ntoa(remoto.sin_addr),  n, ip->ttl);
  free(dados);
  close(mysock);
  close(sockicmp);

  return 0;
}


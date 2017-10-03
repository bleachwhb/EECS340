#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <deque>
#include <iostream>

#include "Minet.h"
#include "tcpstate.h"


using std::cout;
using std::endl;
using std::cerr;
using std::string;
const  unsigned int tcp_header_length=5;
const unsigned int TCP_MAX_DATA=TCP_MAXIMUM_SEGMENT_SIZE;
std::deque<Packet> gbnpkt;
MinetHandle mux, sock;

void  sendPacket(ConnectionToStateMapping<TCPState> &connState, unsigned datalen);

IPHeader creatiph(Connection c, unsigned len) {
	IPHeader ih;
	ih.SetProtocol(IP_PROTO_TCP);
	ih.SetSourceIP(c.src);
	ih.SetDestIP(c.dest);
	ih.SetTotalLength(len + TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
	return ih;
}

TCPHeader creattcph(Packet p, Connection c, unsigned int seq, unsigned int ack, unsigned int num, ConnectionToStateMapping<TCPState> cs) {
	TCPHeader th;;
        th.SetSourcePort(c.srcport,p);
	th.SetDestPort(c.destport,p);
	th.SetSeqNum(seq,p);
	th.SetAckNum(ack,p);
	th.SetHeaderLen(tcp_header_length, p);	
        if(num==1) {
		  unsigned char flag='\0';
		  SET_SYN(flag);
		  SET_ACK(flag);
		  th.SetFlags(flag, p);
	} else if(num==2) {
		  unsigned char flagsack='\0';
		  SET_ACK(flagsack);
		  th.SetFlags(flagsack, p);
	} else if(num==3) {
		  unsigned char flagsnew='\0';
		  SET_SYN(flagsnew);
		  th.SetFlags(flagsnew, p);
	} else if(num==4) {
		  unsigned char flagscl='\0';
		  SET_FIN(flagscl);
                  SET_ACK(flagscl);
		  th.SetFlags(flagscl, p);
	} else if(num==5) {
		  unsigned char flagssy;
		  SET_FIN(flagssy);
		  th.SetFlags(flagssy, p);
	} else if(num==6) {
		  unsigned char flagscw='\0';
		  SET_FIN(flagscw); 
                  SET_ACK(flagscw);
		  th.SetFlags(flagscw, p);
	} else if(num==7) {
		  unsigned char flagsp='\0';
        	  SET_PSH(flagsp);
        	  SET_ACK(flagsp);
        	  th.SetFlags(flagsp, p);
	}       
        th.SetWinSize(cs.state.TCP_BUFFER_SIZE-cs.state.RecvBuffer.GetSize(), p);
	return th;
}


//void tryss(){static int t =10;}
int main(int argc, char *argv[])
{
  //MinetHandle mux, sock;

  //cerr<<t<<"&&&&&&&&***********"<<endl<<endl;
  MinetInit(MINET_TCP_MODULE);
  cerr << "TCP minet on!\n ";
  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  MinetEvent event;
  Time timeout(1);
  Time timeInterval(2);
  ConnectionList<TCPState> clist; 
  Packet sndpkt; 
   
  while (MinetGetNextEvent(event,timeout)==0) {
	
	SockRequestResponse repl;
  	Packet p;
  	IPHeader ih;
  	TCPHeader th;
	ConnectionToStateMapping<TCPState> newc;
           
    if(event.eventtype==MinetEvent::Timeout){
       /*cerr<<endl<<"------------Timeout-----------"<<endl;*/
       for (ConnectionList<TCPState>::iterator i = clist.begin(); i != clist.end(); ++i) {
          if((*i).timeout+timeInterval<Time()){
             switch((*i).state.GetState()){
                case ESTABLISHED:
                     if(gbnpkt.size()>=1){
                         cerr<<"data transfer time out"<<endl;
                         for(std::deque<Packet>::iterator j=gbnpkt.begin();j!=gbnpkt.end();j++){
                               MinetSend(mux,*j);
                              
                         }
                         (*i).timeout=Time();
		     }
                     break;
                case SYN_SENT:
                     if(!(*i).state.ExpireTimerTries()){
                         cerr<<endl<<"Reconnect"<<endl;
                         MinetSend(mux,sndpkt);
                         (*i).timeout=Time();
                     }else{
                         cerr<<endl<<"Go to Close"<<endl;
                         clist.erase(i);
                         repl.connection=(*i).connection;
                         repl.type=STATUS;
		         repl.bytes=0;
		         repl.error=EOK;
                         MinetSend(sock,repl);
		         //(*i).state.SetState(CLOSED);
                     }
                     break;
                case SYN_RCVD:
                     cerr<<endl<<"Resend syn ack"<<(*i).state.GetState()<<endl;
                     MinetSend(mux,sndpkt);
                     (*i).timeout=Time();
                     break;
                case FIN_WAIT1:
                     cerr<<endl<<"Resend fin"<<endl;
                     MinetSend(mux,sndpkt);
                     (*i).timeout=Time();
                     break;

                default:
                     break;
               }
            }else if(Time()-(*i).timeout>=2*Time(2)){
                switch((*i).state.GetState()){
                case TIME_WAIT:
                     cerr<<endl<<"Time wait: 2MSL"<<endl;
                     clist.erase(i);
 		     //(*i).state.SetState(CLOSED);
                     cerr<<"GO TO CLOSED"<<endl;
                     break;
                default:
                     break;
		}
             }
          }

    } else if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
	cerr << "Unknown event ignored.\n ";
	MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
 
    } else {
      cerr<<"event handle: "<<event.handle<<std::endl;
      cerr<<"mux: "<<mux<<'\n';
      cerr<<"sock: "<<sock<<"\n\n";

      if (event.handle==mux) {

	Packet pc;
        MinetReceive(mux,pc);

        unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(pc);     
        pc.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
        IPHeader ipl=pc.FindHeader(Headers::IPHeader);

        unsigned char iphlen;
        short unsigned int totallen;
	Connection c;
        ipl.GetHeaderLength(iphlen);
        ipl.GetTotalLength(totallen);
	ipl.GetDestIP(c.src);
	ipl.GetSourceIP(c.dest);
	ipl.GetProtocol(c.protocol);
        TCPHeader tcph=pc.FindHeader(Headers::TCPHeader);
        bool checksumok=tcph.IsCorrectChecksum(pc);

	tcph.GetDestPort(c.srcport);
	tcph.GetSourcePort(c.destport);

        unsigned short int rwnd;
        tcph.GetWinSize(rwnd);

	ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
        		    
	if (cs!=clist.end()) {

	 unsigned int seq,ack;
         tcph.GetAckNum(seq);
	 tcph.GetSeqNum(ack);

	 unsigned char flags;
	 tcph.GetFlags(flags);
	
          switch((*cs).state.GetState()){
	       case CLOSED: 
		    break;
	       case LISTEN:
              
                    cerr<<endl<<"Status::LISTEN to SYN_RCVD"<<endl;	
    		    if(IS_SYN(flags) && checksumok){               

                      newc.connection=c;
                      newc.state=TCPState(seq,SYN_RCVD,NUM_SYN_TRIES);
                      newc.timeout=Time();
                      newc.state.SetSendRwnd(rwnd);
			
		      ih = creatiph(c,0);
		      p.PushFrontHeader(ih);

		      ack++;
		      th = creattcph(p,c,seq,ack,1,newc);

                      cerr<<endl<<endl<<"IP header is "<<ih<<endl<<endl;
		      cerr<<endl<<endl<<"TCP header is "<<th<<endl<<endl;
		      p.PushBackHeader(th);
		      MinetSend(mux,p);
                      
                      newc.state.SetLastRecvd(ack-1);       
                      newc.state.SetLastSent(seq);          //initial last sent
                      newc.state.SetLastAcked(seq);
                      clist.push_front(newc);
		      clist.erase(cs);
                      sndpkt=p;
		    }
                    
                    break;

	      case SYN_RCVD:

		   cerr<<endl<<" Status:SYN_RCVD"<<endl;

		   if(IS_ACK(flags) && checksumok){  
		      (*cs).state.SetState(ESTABLISHED);
                      cerr<<"status: SYN_RCVD to Establish\n";
                      (*cs).state.SetSendRwnd(rwnd);
                      (*cs).state.SetLastRecvd(ack-1);                    ///
                      (*cs).state.SetLastAcked(seq);
                    
                      repl.connection=(*cs).connection;
                      repl.type=WRITE;
		      repl.bytes=0;
		      repl.error=EOK;
		      MinetSend(sock,repl);
                   }
              	   break;

	      case SYN_SENT:

	           cerr<<endl<<"Status:SYN_SENT"<<endl;
		   if(IS_SYN(flags)&&IS_ACK(flags)&&checksumok){
		      cerr<<"SYN_ack"<<endl;

		      ih = creatiph(c,0);
		      p.PushFrontHeader(ih);

		      

		      ack++;
		      th = creattcph(p,c,seq,ack,2,(*cs));   
                      
		      p.PushBackHeader(th);
		      MinetSend(mux,p);

                   
                      (*cs).state.SetLastSent(seq-1);
                      (*cs).state.SetLastAcked(seq);
                      (*cs).state.SetLastRecvd(ack-1);                    
                      (*cs).state.SetState(ESTABLISHED);
                      (*cs).state.SetSendRwnd(rwnd);

                      sndpkt=p;

                      cerr<<endl<<"ih: "<<ih<<endl;
	    	      cerr<<endl<<"th: "<<th<<endl;
			
		      repl.type = WRITE;
		      repl.connection = c;
		      repl.error = EOK;
		      repl.bytes = 0;
		      MinetSend(sock, repl);
		      cerr<<"SYN+ACK SYN-Sent to Establish"<<(*cs).state.GetState()<<endl;
		   }
 	           break;
	       case ESTABLISHED:
                    cerr<<endl<<"Status:ESTABLISHED"<<endl;
		
                    if(IS_FIN(flags) && checksumok){
			cerr<<endl<<"RECEIVE FIN"<<endl;

		        ih = creatiph(c,0);
			p.PushFrontHeader(ih);
		        ack=ack+1;
		        th = creattcph(p,c,seq,ack,2,(*cs));  
			
                        p.PushBackHeader(th);
                        MinetSend(mux,p);
			(*cs).state.SetState(CLOSE_WAIT);
                        (*cs).state.SetLastRecvd(ack-1);
                        (*cs).state.SetLastSent(seq);
                        (*cs).state.SetLastAcked(seq);
                        (*cs).timeout=Time();
                        (*cs).state.SetSendRwnd(rwnd);


			repl.type = WRITE;
		    	repl.connection = (*cs).connection;
		    	repl.error = EOK;
		    	repl.bytes = 0;
			MinetSend(sock, repl);
                        cerr<<"	FIN:ESTABLSIH TO CLOSED"<<(*cs).state.GetState()<<endl;
                        sndpkt=p;

		    }else if(IS_PSH(flags) && IS_ACK(flags)){         //receiver side
                      
                        if(ack==(*cs).state.GetLastRecvd()+1 && checksumok){

                                cerr<<endl<<"RECEIVE DATA"<<endl;	                       
        	            
                                (*cs).state.SetSendRwnd(rwnd);

                	        unsigned int datalen=totallen-(iphlen<<2)-tcphlen;
                    	   	Buffer &data = pc.GetPayload().ExtractFront(datalen);
      		                (*cs).state.RecvBuffer.AddBack(data);

        	                cerr<<endl<<"DATA RECEIVED SUCCESS: "<<data<<" LEN: "<<datalen<<endl;

                	        (*cs).state.SetLastRecvd(ack-1+datalen);         //received packet seq + data length
             		        (*cs).state.SetLastAcked(seq);               //set ack, used to resent unacked data  		                    

		        	ih = creatiph(c,0);
    	                        p.PushFrontHeader(ih);

  	                         seq=(*cs).state.GetLastSent()+1;
          	                 ack=(*cs).state.GetLastRecvd()+1;;
		       		th = creattcph(p,c,seq,ack,2,(*cs));  // set_ack   
		        
	
	              		p.PushBackHeader(th);
	                        MinetSend(mux,p);
	                        (*cs).timeout=Time();

 
			 }else{
                                (*cs).state.SetSendRwnd(rwnd);

        	                cerr<<endl<<"WRONG ACK_NUMBER"<<endl;

		        	ih = creatiph(c,0);
    	                        p.PushFrontHeader(ih);

  	                        seq=(*cs).state.GetLastSent()+1;
          	                ack=(*cs).state.GetLastRecvd()+1;
		       		th = creattcph(p,c,seq,ack,2,(*cs));
		     
	
	              		p.PushBackHeader(th);
	                        MinetSend(mux,p);
                         }

                   }else if(IS_ACK(flags)&&ack==(*cs).state.GetLastRecvd()+1&&checksumok){  
                                                                                     
                        cerr<<endl<<"Recieve Ack packet"<<endl;                      
                        (*cs).state.SetLastAcked(seq);               //received ack, used to resent unacked data
                        (*cs).state.SetSendRwnd(rwnd);

                        cerr<<endl<<"Remove this Packet from buffer deque"<<endl;
                        unsigned int sn=seq;
                        unsigned tl;
                        TCPHeader t;

                        bool pop=false;
                        while(!gbnpkt.empty()){
                            tl=20;
                            gbnpkt[0].ExtractHeaderFromPayload<TCPHeader>(tl);
                            t=gbnpkt[0].FindHeader(Headers::TCPHeader);
                            t.GetSeqNum(sn);
                            if(sn<=seq){
                               gbnpkt.pop_back();
                               pop=true;
                            }                        
                        }     
                        if(pop && !gbnpkt.empty()){
                             (*cs).timeout=Time();
                        }                    
                   }
		   break;

               case FIN_WAIT1:

                    cout<<endl<<"Status:FIN_WAIT1"<<endl;
	            if(IS_FIN(flags)&&IS_ACK(flags)&&checksumok)
	            { 
                      (*cs).state.SetSendRwnd(rwnd);
		      ih = creatiph((*cs).connection,0);
		      p.PushFrontHeader(ih);
		   
		      ack=ack+1;
		      th = creattcph(p,(*cs).connection,seq,ack,2,(*cs));
		      (*cs).state.SetState(TIME_WAIT);
                      (*cs).timeout=Time();
		      p.PushBackHeader(th);
	              MinetSend(mux,p);
                      	        
	            }
                    else if(IS_ACK(flags)&&checksumok)
		    {
		      (*cs).state.SetState(FIN_WAIT2);
	            }
                    break;
		    
	       case FIN_WAIT2:
		    cout<<endl<<"Status:FIN_WAIT2"<<endl;
                    if(IS_FIN(flags)&&checksumok)
                    {
                      (*cs).state.SetSendRwnd(rwnd);
		      ih = creatiph((*cs).connection,0);
		      p.PushFrontHeader(ih);

		      th = creattcph(p,(*cs).connection,seq,ack,2,(*cs));
		      (*cs).state.SetState(TIME_WAIT);
                       
		      p.PushBackHeader(th);
                      MinetSend(mux,p);
                    }
		    break;

	       case LAST_ACK:

		    cerr<<endl<<"STATUS:LAST_ACK"<<endl;
		    if(IS_ACK(flags)){
		      (*cs).state.SetState(CLOSED);
		       clist.erase(cs);
		      cerr<<endl<<"CLOSE THIS CONNECTION"<<endl;
		    }
		    break;

	       case TIME_WAIT:
                    
                     cerr<<endl<<"STATUS:TIME_WAIT"<<endl;
                     (*cs).timeout=Time();
                     break;

               default:
                   cerr<<endl<<"DEFAULT VALUE"<<endl;
	  }
	} else {

          cout<<endl<<"ICMP"<<endl;
       }
	
        
      }
      if (event.handle==sock) {
        SockRequestResponse s;
        MinetReceive(sock,s);
        
        cerr <<endl<< "Received Socket Request:" << s << endl;
	
        Connection c=s.connection;
        ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);

        unsigned int seq,ack;
       
        if(cs == clist.end()){
	    cerr<<"s.type: "<<s.type<<endl;
	    ConnectionToStateMapping<TCPState> cm;
	    switch (s.type) {
	    case CONNECT:
	        {
		   cerr << "Connect success\n ";
		   
		   cm.timeout=Time();
                   cm.connection=s.connection;
                   cm.state=TCPState(seq,SYN_SENT,NUM_SYN_TRIES);

		   ih = creatiph(s.connection,0);
		   p.PushFrontHeader(ih);
		  
		   th = creattcph(p,s.connection,seq,ack,3,cm);

		   p.PushBackHeader(th);

		   MinetSend(mux,p);
	           
                   cm.state.SetLastSent(seq);
                   clist.push_front(cm);

		   repl.type = STATUS;
		   repl.connection = s.connection;
		   repl.bytes = 0;
		   repl.error = EOK;
		   MinetSend(sock, repl);
		   
                   sndpkt=p;        
		}
		break;
	    case ACCEPT: 

		cerr << "Accept"<<std::endl;
	
		repl.type=STATUS;
		repl.connection=s.connection;         
		repl.bytes=0;
		repl.error=EOK;
		MinetSend(sock,repl);

		cm.connection=s.connection;
		cm.state=TCPState(seq,LISTEN, 10);   
		clist.push_back(cm);	     
	        break;

	    default:
              break;
	   }
	}else{	  
        
          switch((*cs).state.GetState()){

	     case ESTABLISHED:                
	       switch(s.type){
		       case CONNECT:
			 repl.type=WRITE;
			 repl.bytes=0;
			 repl.error=EOK;
			 repl.connection=s.connection; 
			 MinetSend(sock,repl);
			 break;
                       
                        case ACCEPT:
			 repl.type=WRITE;
			 repl.bytes=0;
			 repl.error=EOK;
			 repl.connection=s.connection; 
			 MinetSend(sock,repl);
		         break;
		       case WRITE:
			  {
			 	cerr << endl<<"WRITE"<<endl;

                                SockRequestResponse repl;
                                if((*cs).state.TCP_BUFFER_SIZE-(*cs).state.SendBuffer.GetSize()>=s.data.GetSize()){
				  
                                  (*cs).state.SendBuffer.AddBack(s.data);
                                  cerr<<endl<<"data: "<<s.data<<endl;
				  repl.type=STATUS;
				  repl.connection=s.connection;
				  repl.bytes=s.data.GetSize();
				  repl.error=EOK;
				  MinetSend(sock,repl);
                                }else{     
				  repl.type=STATUS;
				  repl.connection=s.connection;
				  repl.bytes=0;
				  repl.error=EOK;
				  MinetSend(sock,repl);

                                }
                           }
			   break;

		       case CLOSE:
                        	{
				cerr<<"\nCLOSE SOCK\n";
		                ih = creatiph((*cs).connection,0);
		   		p.PushFrontHeader(ih);
		  
                                seq=(*cs).state.GetLastSent()+1;
                                ack=(*cs).state.GetLastRecvd()+1; 

		   		th = creattcph(p,(*cs).connection,seq,ack,4,(*cs));

		 	  	(*cs).state.SetState(FIN_WAIT1);
		 	  	p.PushBackHeader(th);

				cerr<<"\nih: "<<ih;
				cerr<<"\nth: "<<th<<endl;

                    		MinetSend(mux,p);
                                (*cs).timeout=Time();                             
                                sndpkt=p;
				cerr << "Establish Close\n ";
                                
                                (*cs).state.SetLastSent(seq);
                         	}
			 	break;
		       	default:
				break;
		       }
               	break;
             case SYN_RCVD:
                  switch(s.type){
                      case CLOSE:


		        ih = creatiph((*cs).connection,0);

		   	p.PushFrontHeader(ih);


		   	th = creattcph(p,(*cs).connection,seq,ack,5,(*cs));

		   	(*cs).state=TCPState(seq,FIN_WAIT1,10);

		   	p.PushBackHeader(th);
                    	MinetSend(mux,p);
		
			 cerr << "SYN_RCVD Close\n ";
                        
                  }
                  break;
	     case CLOSE_WAIT:

		    cerr<<endl<<"Status:CLOSE_WAIT"<<endl;
		  if(s.type == CLOSE){
		   ih = creatiph((*cs).connection,0);
		   p.PushFrontHeader(ih);

		   seq=(*cs).state.GetLastSent();         
                   ack=(*cs).state.GetLastRecvd()+1;
		   th = creattcph(p,(*cs).connection,seq,ack,6,(*cs));
		   
		   p.PushBackHeader(th);

                   MinetSend(mux,p);
                    (*cs).timeout=Time();
                        
                   (*cs).state.SetLastSent(seq);                  
                   (*cs).state.SetState(LAST_ACK);

		   cerr<<endl<<"ih: "<<ih<<endl;
		   cerr<<endl<<"th: "<<th<<endl;
		  }
		    break;
	       case CLOSING:
		    break;
	       
	       
	      default: break;
  	}
      }
    }
   }
	 for (ConnectionList<TCPState>::iterator i = clist.begin(); i != clist.end(); ++i) {
	      if((*i).state.SendBuffer.GetSize()>0){
	      unsigned datalen = MIN_MACRO(TCP_MAX_DATA, (*i).state.SendBuffer.GetSize()); 
	      ConnectionToStateMapping<TCPState> &connState = *i;
	      sendPacket(connState,datalen);
	     }
	     if((*i).state.RecvBuffer.GetSize()>0){
	    Buffer &data=(*i).state.RecvBuffer.ExtractFront((*i).state.RecvBuffer.GetSize());
	    unsigned int datalen=data.GetSize();  
	    SockRequestResponse write(WRITE,
		                      (*i).connection,
		                      data,
		                      datalen,
		                      EOK);
		                
	    MinetSend(sock,write);
	     }
	}
  }
  return 0;
}

void  sendPacket(ConnectionToStateMapping<TCPState> &connState, unsigned datalen)
{
if(connState.state.GetRwnd()>=datalen&&connState.state.GetLastSent()+1<connState.state.GetN()+connState.state.GetLastAcked()){  
        Packet temp(connState.state.SendBuffer.ExtractFront(datalen));
        IPHeader ih;
	TCPHeader th;
	ih = creatiph(connState.connection,datalen);
        temp.PushFrontHeader(ih);
	   			
	unsigned int seq=connState.state.GetLastSent()+1;  
        unsigned int ack=connState.state.GetLastRecvd()+1;
	
	th = creattcph(temp,connState.connection,seq,ack,7,connState);

        temp.PushBackHeader(th);
        MinetSend(mux,temp);

        connState.timeout=Time();
        connState.state.SetLastSent(seq-1+datalen);
        gbnpkt.push_back(temp);        
    }
    if(gbnpkt.size()==1){
       connState.timeout=Time();
    }
}

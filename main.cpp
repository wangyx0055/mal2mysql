#include <oPen/oPenpcap.cpp>
#include <oPen/oPen.h>
#include <oPen/oPenMYSQL.cpp>

void oPenpcap::cb(u_char *arg1, const struct pcap_pkthdr *arg2, const u_char *arg3)
{
	
	oPenpcap obj;	
	
	register struct ip *IP=(struct ip *)(arg3+sizeof(struct ether_header));		
 	register char *str=(char *)(arg3+sizeof(struct ether_header)+sizeof(struct ip)+sizeof(struct tcphdr)); 	
		
	if(strstr(str, "@"))
	obj.operation(str);
}

int oPenpcap::operation(char * str)
{
	
	if(strlen(str)<11)
	return 1;
	
	register int e=0, a=48, pos=0, flag;
	char retolno[strlen(str)];
	
	while(pos<=strlen(str))
	{
	flag=0;	

		//0-9
		for(a=48;a<=57;a++)
		if(str[pos]==a) flag=1;
						
		//a-b	
		for(a=97;a<=122;a++)
		if(str[pos]==a) flag=1;
	
		//@-Z
		for(a=64;a<=90;a++)
		if(str[pos]==a) flag=1;
			
		if(str[pos]==46 || str[pos]==95 /*|| str[pos]==60 || str[pos]==62 || str[pos]==47*/)
		flag=1;
		
		if(flag==1)
		{

			if(e==0 && (str[pos]=='@' || str[pos]=='.'))
			{
				
			if(strlen(str)>pos)
			pos++;
						
			continue;
			}
			
			retolno[e++]=str[pos];
			retolno[e+1]='\0';
			pos++;
			
			/*
			if(strstr(retolno, "@") && strlen(retolno)>4)
			cout << "hasta ahora .. (" << e  << ") " << "'" << retolno << "'" <<  endl;
			*/
			
			
			if(strlen(retolno)>11  && strstr(retolno, "@") && strstr(retolno, ".")  && (strstr(retolno, "com") || strstr(retolno, "net")))
			{
				oPen obj;
				char tmp[512];
				
					sprintf(tmp, "insert into logins values(\"%s\", \"\")", retolno);				
					
					obj.mysql("localhost", "audit", "oPen", "CURLE_OK", tmp, 9000, 1);					
					retolno[0]='\0';
			}
						
		}
		
			else
			{
				
				/*if(str[pos]=='<')
				{
						do					
						{
							
							if(strlen(str)>pos)pos++;	
							
						}while(str[pos]!='>');
				
				pos++;
				continue;
				}*/
				
				/*if(str[pos]=='&' && str[pos+1]=='#' && str[pos+2]=='0' && str[pos+3]=='6' && str[pos+4]=='4' && str[pos+5]==';')
				{
					strncat(retolno, "@", strlen(str));
					pos=pos+5;
					continue;	
				}*/

				//cout << "la corta (" << (int) str[pos] << ") '" << str[pos] << "'" << endl;								
				retolno[0]='\0';
				e=0;				
				
			pos++;
			}
											
	}
	

return 0;	
}

int main()
{
	oPenpcap obj;	
	obj.listen("eth0", "tcp and port 80");
}

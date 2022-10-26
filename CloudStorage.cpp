#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/stat.h>
#include <iostream>

#include "CloudStorage.hh"
using namespace std;


/// receive file 
int write_all(FILE *file, const void *buf, int len)
{
    const char *pbuf = (const char *) buf;

    while (len > 0)
    {
        int written = fwrite(pbuf, 1, len, file);
        if (written < 1)
        {
            printf("Can't write to file");
            return -1;
        }

        pbuf += written;
        len -= written;
    }

    return 0;
}

int read_all(int sock, void *buf, int len)
{
    char *pbuf = (char *) buf;
    int total = 0;
    
	
    while (len > 0)
    
    { 	int rval = read(sock, pbuf, len);
	 
       
        if (rval < 0)
        {
            // if the socket is non-blocking, then check
            // the socket error for WSAEWOULDBLOCK/EAGAIN
            // (depending on platform) and if true then
            // use select() to wait for a small period of
            // time to see if the socket becomes readable
            // again before failing the transfer...

            cout<<"Can't read from socket";
            cout.flush();
            return -1;
        }

        if (rval == 0)
        {
            cout<<"Socket disconnected";
            cout.flush();
            return 0;
        } 

        pbuf += rval;
        len -= rval;
        total += rval;
    }

cout<< string("Total is ")+pbuf;
cout<<"\n Total \n";
cout<< total;
cout.flush();
    return total;
}


int RecvFile(int sock,   char const* filename) 
{ 


  int rval; 
    char buf[0x1000];
    
    // check if the file is already exists
    FILE *file;
    
    
    cout<<std::string("The file name is " )+filename+"\n";
    cout.flush();
    
	file = fopen(filename, "rb+");
	if(file == NULL) //if file does not exist, create it
	{
	    file = fopen(filename, "wb");
   
    if (!file)
    {
        cout<<"Can't open file for writing";
        cout.flush();
        return -1;
    }

    // if you need to handle files > 2GB,
    // be sure to use a 64bit integer, and
    // a network-to-host function that can
    // handle 64bit integers...
    long size = 0;
    /// test reading in function
   

int return_status = read(sock, &size, sizeof(size));



   if ( return_status>0)
   {
       size = ntohl(size);
       while (size > 0)
       {
           rval = read_all(sock, buf, min(long(sizeof(buf)), size));
           if (rval < 1)
               break;

           if (write_all(file, buf, rval) == -1)
               break;
       size -= rval;
       } 
   }
   

   fclose(file); 
   return 1;
   }
	else // file is already exists
	{
		 cout<< "File already exists";
       cout.flush();
		 fclose(file); 
		return -1;
	}

   
    
} 	
	
/// end of receive files fucntions

// send file functions


int send_all(int sock, const void *buf, int len)
{
    const char *pbuf = (const char *) buf;

  
     
      
    while (len > 0)
    {
        int sent = send(sock, pbuf, len, 0);
       
        if (sent < 1)
        {
            // if the socket is non-blocking, then check
            // the socket error for WSAEWOULDBLOCK/EAGAIN
            // (depending on platform) and if true then
            // use select() to wait for a small period of
            // time to see if the socket becomes writable
            // again before failing the transfer...

            printf("Can't write to socket");
            return -1;
        }

        pbuf += sent;
        len -= sent;
    }

    return 0;
}

int SendFile(int sock, char const * filename) 
{ 

    char buf[0x1000]; 
    
    struct stat s;

    if (stat(filename, &s) == -1)
    {
        printf("Can't get file info"); 
        return -1;
    }

    FILE *file = fopen(filename, "rb"); 
    if (!file)
    {
        printf("Can't open file for reading"); 
        return -1;
    }

    // if you need to handle files > 2GB,
    // be sure to use a 64bit integer, and
    // a host-to-network function that can
    // handle 64bit integers...
    long size = s.st_size;
    // network sending /seraliztion
    long tmp_size = htonl(size);
    
   

// Write the number to the opened socket
  int val=send(sock, &tmp_size, sizeof(tmp_size),0);
   
   
    
    if (val>0)
    {
        while (size > 0)
        { 
            int rval = fread(buf, 1, min(long(sizeof(buf)), size), file); 
            if (rval < 1)
            {
                printf("Can't read from file");
                break;
            }

            if (send_all(sock, buf, rval) == -1)
                break;

            size -= rval;
        }
    }
    
    fclose(file);
    
    return 1;
} 
// end of send file functions




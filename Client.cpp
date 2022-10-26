// Client side C/C++ program to demonstrate Socket
// programming
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/stat.h>
#include <iostream>
#include "CloudStorage.hh"
#include <sys/ioctl.h>

using namespace std;

#define PORT 8080






int main(int argc, char const* argv[])
{
	int sock = 0, valread, client_fd;
	char* passwordRequest = "Please Enter Your Password";
	char* wrongPassword="Your password is wrong";

	
	struct sockaddr_in serv_addr;
	char* hello = "Hello from client";
	char buffer[1024] = { 0 };
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Socket creation error \n");
		return -1;
	}
	//// set the mode blcoking for the socket
	int iMode=0;
	ioctl(sock, FIONBIO, &iMode); 

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	// Convert IPv4 and IPv6 addresses from text to binary
	// form
	if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)
		<= 0) {
		printf(
			"\nInvalid address/ Address not supported \n");
		return -1;
	}

	if ((client_fd
		= connect(sock, (struct sockaddr*)&serv_addr,
				sizeof(serv_addr)))
		< 0) {
		printf("\nConnection Failed \n");
		return -1;
	}
	// authentication logic
    valread=read(sock, buffer, 1024);
	printf("%s\n", buffer);
	string username;
	cin>> username;
	const char *cstr = username.c_str();
	// send username
	send(sock, cstr, username.size(), 0);
	//wait for server response
	memset(buffer, 0, sizeof buffer);
	valread=read(sock, buffer, 1024);
	
	string receivedText=buffer;
	printf("%s\n", buffer);
	if(passwordRequest==receivedText)
	{
			string password;
		    cin>> password;
		   const  char *cstr1 = password.c_str();
		    // send the password
		    send(sock, cstr1, password.size(), 0);
		    // wait the server response
		     memset(buffer, 0, sizeof buffer);
		    valread = read(sock, buffer, 1024);
		    
	        printf("%s\n", buffer);
	        receivedText=buffer;
	        if(wrongPassword==receivedText) // wrong password
	        {
	        	exit(0);
			}
			else // correct password
			{
				// authentication done
				
			
	        
	int i=0;
	while(i<10)
	    {
	        	i++;
	        
	
	        // read and print the operations
	        
	        string operation;
		    cin>> operation;
		    
		    //send the operation to the server
		    cstr1 = operation.c_str();
			send(sock, cstr1, operation.size(), 0);
			//printf("Operation Sent \n");
			
			// wait until receving the operation from the server
			memset(buffer, 0, sizeof buffer);
			
			//read the word "received" only not the entrie buffer
			valread = read(sock, buffer, 8);
		    printf("%s\n", buffer);
		    
		if(operation=="0")
		{
				
			// send the file name to the server
			cout<< "Enter the filename \n";
			string filename;
		    cin>> filename;
		    
		    const char * cstr2 = filename.c_str();
			send(sock, cstr2, filename.size(), 0);
			
			
			printf("FileName Sent \n");
			
			string fullFilePath = "./"+username+"_local/"+filename; // Added some space for array[0]
            //strcat( fullFilePath, filename );
            
			// send the file to the sever
			int result= SendFile(sock, fullFilePath.c_str());
			if(result==1)
			{
			printf("File Sucessfully Sent \n");
			// print the  result from the server
			
			}
			else
			{
				printf("File not Sent \n");
			}
			memset(buffer, 0, sizeof buffer);
		    valread = read(sock, buffer, 1024);
		    printf("%s\n", buffer);
			
			
		}
		else if(operation=="1")
		{
			cout<< "Enter the filename \n";
			string filename;
		    cin>> filename;
		
		// send the file name to the server
		    const char* cstr2 = filename.c_str();
			send(sock, cstr2, filename.size(), 0);
		    // receive the file from the server
		    
		    string fullFilePath = "./"+username+"_local/"+filename; // Added some space for array[0]
            //strcat( fullFilePath, fullFilePath );
		    
		    int result=RecvFile(sock, fullFilePath.c_str());
		    if(result==1)
			 {
			 		cout<< "File Successfully Received \n";
			 }
			 else
			 {
			 		cout<< "File not Received \n";
			 }
			 memset(buffer, 0, sizeof buffer);
			  valread = read(sock, buffer, 1024);
		    printf("%s\n", buffer);
		} else if(operation=="2")
		{
				cout<< "Enter the filename \n";
			string filename;
		    cin>> filename;
		    
		    // send the file name to the server
		    const char* cstr2 = filename.c_str();
			send(sock, cstr2, filename.size(), 0);
			memset(buffer, 0, sizeof buffer);
	    valread = read(sock, buffer, 1024);
		printf("%s\n", buffer);
			
		    
		}else if(operation=="3")
		{
		operation="";
		memset(buffer, 0, sizeof buffer);
		valread = read(sock, buffer, 1024);
		if(valread==0)
		{
			cout<< "server disconneted";
		}
		printf("%s\n", buffer);
		
	
		
		
		
		
		} else if(operation=="4")
		 {
		 	cout<< "Enter the filename \n";
			string filename;
		    cin>> filename;
		    
		    // send the file name to the server
		    const char* cstr2 = filename.c_str();
			send(sock, cstr2, filename.size(), 0);
			
			memset(buffer, 0, sizeof buffer);
			valread = read(sock, buffer, 1024);
		    printf("%s\n", buffer);
		    
		    string newFileName;
		    cin>> newFileName;
		    // send the new file name to the server
		    cstr2 = newFileName.c_str();
			send(sock, cstr2, newFileName.size(), 0);
			
			
			// print the responce from the server
			
			memset(buffer, 0, sizeof buffer);
			valread = read(sock, buffer, 1024);
		    printf("%s\n", buffer);
		    
			
		 }
		 else if(operation=="5")
		 {
		
	        //memset(buffer, 0, sizeof buffer);
	      
//		    valread = read(sock, buffer, 1024);
//		    printf("%s\n", buffer);
			cout<<"Logged out\n";

		 	 exit(0);
		 	 
		 }
	    }// end while
	        
	  }
		   
	}
	
    

	// closing the connected socket
	close(client_fd);
	return 0;
}


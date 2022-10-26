// Server side C/C++ program to demonstrate Socket
// programming
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <unordered_map>
#include <iostream>
#include <syscall.h>
#include "CloudStorage.hh"
#include <dirent.h>
#include <sys/ioctl.h>

#define PORT 8080
using namespace std;

std::unordered_map<std::string,std::string> users;



void* handle_connection(void *arg)
{
	
	
	/* handle the connection using the socket... */
    char* userNameRequest = "Please Enter Your Name";
    char* passwordRequest = "Please Enter Your Password";
    char* hello = "Welcome to the File Managment System\n ";
    char* wrongPassword="Your password is wrong";
    char* wrongUserName="The username is incorrect";
    char* operations="Please select what you would like to do:\n 0:Upload , 1:Download, 2: Delete, 3:List, 4:Rename, 5:Logout";
    char* wrongOperation="The operation is invalids";
    char* operationReceived="Received";
    char * operationSucessed="The opration completed successfully\n";
    char * newFileName="Enter the new file name";
    char * userLoggedOut="Logged out successfully\n";
	int valread;
    int client_sock = *(int*)arg;
    
   


    char buffer[1024] = { 0 };
    
    
    send(client_sock, userNameRequest, strlen(userNameRequest), 0);
    
    //receive the username
    valread = read(client_sock, buffer, 1024);
	string userName=buffer;
	//printf(buffer);
	if (users.find(userName) == users.end())
	{
		//  not found
	  send(client_sock, wrongUserName, strlen(wrongUserName), 0);

	}
	else
	{
		// found
	
		send(client_sock, passwordRequest, strlen(passwordRequest), 0);
		
		string password=users.at(userName);
		
		//receive the password
		memset(buffer, 0, sizeof buffer);
		valread = read(client_sock, buffer, 1024);
		string receivedPassword=buffer;
		if(receivedPassword==password)
		{
			send(client_sock, hello, strlen(hello), 0);
			
			// authentication successful
			send(client_sock, operations, strlen(operations), 0);
			// read the selected operation
			
			
			
			int i=0;
			while(i<10)
			{
			i++;
				
			
			memset(buffer, 0, sizeof buffer);
			valread = read(client_sock, buffer, 1024);
			
			string operation=buffer;
			
			cout<< "the operaion is " +operation+"\n";
			
			cout.flush();
			send(client_sock, operationReceived, strlen(operationReceived), 0);
			
			if(operation=="0")
			{
				//user uploads file
				 // receive the file name
			memset(buffer, 0, sizeof buffer);
			 valread = read(client_sock, buffer, 1024);
			 
			 // start receving operation and wait for result
			 
			 string filename = "./"+userName+"/"+buffer; // Added some space for array[0]
             //strcat( filename, buffer );
            
             
			 int result=RecvFile(client_sock, filename.c_str());
			 if(result==1)
			 {
			 	
			 	send(client_sock, operationSucessed, strlen(operationSucessed), 0);
			 
			 } 
			 else
			 {
			 	// operatin failed 
			 	send(client_sock, wrongOperation, strlen(wrongOperation), 0);
			 
			 }
			 	send(client_sock, operations, strlen(operations), 0);
			}
			else if(operation=="1")
			{
				// user downloads file // server sends the file
				
				// receive the file name from the client
			 memset(buffer, 0, sizeof buffer);
			 valread = read(client_sock, buffer, 1024);
			 // send the file to the client
			 
			 string filename = "./"+userName+"/"+buffer; // Added some space for array[0]
            // strcat( filename, buffer );
             
             
             
             
			 int result =SendFile(client_sock,filename.c_str());
			 if(result==1)
			 {
			 	
			 	send(client_sock, operationSucessed, strlen(operationSucessed), 0);
			 	
			 } 
			 else
			 {
			 	// operations failed 
			 	send(client_sock, wrongOperation, strlen(wrongOperation), 0);
			 	
			 }
			 
				send(client_sock, operations, strlen(operations), 0);
			}
			else if(operation=="2")
			{
				// user deletes  file
				
			// receive the file name from the client
			 memset(buffer, 0, sizeof buffer);
			 valread = read(client_sock, buffer, 1024);
			 
			string filename = "./"+userName+"/"+buffer;
			const int result = remove( filename.c_str() );
			if( result == 0 ){
			  // cout<< "success\n";
			   	send(client_sock, operationSucessed, strlen(operationSucessed), 0);
			} else {
			    
				//cout<<"file not found \n"; // No such file or directory
				send(client_sock, wrongOperation, strlen(wrongOperation), 0);
			}
			 //cout.flush();
			 
			send(client_sock, operations, strlen(operations), 0);
			 
			}
			else if(operation=="3")
			{
				// user shows the files
				std::string path = "./"+userName+"/";
            
			
			DIR *dpdf;
            struct dirent *epdf;
			dpdf = opendir(path.c_str());
			string listOfFiles="";
			if (dpdf != NULL){
			   while (epdf = readdir(dpdf)){
			      listOfFiles+= string(epdf->d_name)+"\n";
			      
			      
			   }
			}
				 
			
			const char* cstr2 = listOfFiles.c_str();
			
			send(client_sock, operationSucessed, strlen(operationSucessed), 0);
			
			send(client_sock, cstr2, listOfFiles.size(), 0);	
			              
			send(client_sock, operations, strlen(operations), 0);
			closedir(dpdf);
				
			}
			else if(operation=="4")
			{
			// receive the file name from the client
			
			//empty the buffer
			memset(buffer, 0, sizeof buffer);
	
			valread = read(client_sock, buffer, 1024);
			
			string filename = "./"+userName+"/"+buffer;
			
			
			send(client_sock, newFileName, strlen(newFileName), 0);
			// receive the new file name of the clinet
			
			 memset(buffer, 0, sizeof buffer);
			valread = read(client_sock, buffer, 1024);
			string newFileName="./"+userName+"/"+buffer;
			//cout<<newFileName;
			//cout<<filename;
			//cout.flush();
		
				
			int result=rename(filename.c_str(), newFileName.c_str());
			// rename succeeds
			if(result==0)
			{
					send(client_sock, operationSucessed, strlen(operationSucessed), 0);
			}
			else // rename fails
			{
				send(client_sock, wrongOperation, strlen(wrongOperation), 0);
			}
			
			send(client_sock, operations, strlen(operations), 0);
			}
			else if(operation=="5")
			{
				
				send(client_sock, userLoggedOut, strlen(userLoggedOut), 0);
				send(client_sock, operations, strlen(operations), 0);
				break;
			}
			else // invalid operation
			{
					send(client_sock, wrongOperation, strlen(wrongOperation), 0);
					send(client_sock, operations, strlen(operations), 0);
			}
			
	}//end while
		}
		else
		{
				send(client_sock, wrongPassword, strlen(wrongPassword), 0);
		}
	}
	
	// closing the connected socket
	close(client_sock);
}


int main(int argc, char const* argv[])
{
	
	users["A"]="1234";
	users["B"]="12345";
	int server_fd, new_socket;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);
	




	// Creating socket file descriptor
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0))
		== 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// Forcefully attaching socket to the port 8080
	if (setsockopt(server_fd, SOL_SOCKET,
				SO_REUSEADDR | SO_REUSEPORT, &opt,
				sizeof(opt))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);


	if (bind(server_fd, (struct sockaddr*)&address,
			sizeof(address))
		< 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	if (listen(server_fd, 3) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	while(1)
	{
		
		
		new_socket = accept(server_fd, (struct sockaddr*)&address,
				(socklen_t*)&addrlen);
				
				//// set the mode blcoking for the socket
	        int iMode=0;
	       ioctl(new_socket, FIONBIO, &iMode); 
				
			
        pthread_t client_threadid;
				
		pthread_create(&client_threadid,NULL,handle_connection,&new_socket);
		
		 
				
	
				
	}




// closing the listening socket
	shutdown(server_fd, SHUT_RDWR);
	return 0;
}




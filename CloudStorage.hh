

#ifndef Cloud
#define Cloud

/// receive file 
int write_all(FILE *file, const void *buf, int len);

int read_all(int sock, void *buf, int len);


int RecvFile(int sock,  char const* filenameRece) ;

/// end of receive files fucntions

// send file functions


int send_all(int sock, const void *buf, int len);

int SendFile(int sock, char const* filename) ;


// end of send file functions

#endif


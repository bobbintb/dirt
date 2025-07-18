#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main() { 
    open("/tmp/test_file", O_CREAT | O_WRONLY, 0644); 
    printf("Created file\n"); 
    unlink("/tmp/test_file"); 
    printf("Deleted file\n"); 
    return 0; 
}

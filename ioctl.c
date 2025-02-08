#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>

#define DEVICE_NAME "/dev/linsec"  // Device file created by your kernel module

// Define three different IOCTL commands
#define IOCTL_SET_VALUE_A _IOW('a', 1, char *)
#define IOCTL_SET_VALUE_B _IOW('b', 2, char *)
#define IOCTL_SET_VALUE_C _IOW('c', 3, char *)
#define IOCTL_SET_VALUE_D _IOW('d', 4, char *)


int main(int argc, char *argv[]) {
    int fd;
    int ret;

    // Ensure the user provides at least two arguments
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ioctl_type> <value>\n", argv[0]);
        return -1;
    }

    char *ioctl_type = argv[1];
    char *input_value = argv[2];

    // Open the device file
    fd = open(DEVICE_NAME, O_RDWR);
    if (fd < 0) {
        perror("Failed to open device file");
        return -1;
    }

    // Determine which IOCTL to execute based on argument
    if (strcmp(ioctl_type, "A") == 0) {
        ret = ioctl(fd, IOCTL_SET_VALUE_A, input_value);
    } else if (strcmp(ioctl_type, "B") == 0) {
        ret = ioctl(fd, IOCTL_SET_VALUE_B, input_value);
    } else if (strcmp(ioctl_type, "C") == 0) {
        ret = ioctl(fd, IOCTL_SET_VALUE_C, input_value);
    } else if (strcmp(ioctl_type, "D") == 0) {
        ret = ioctl(fd, IOCTL_SET_VALUE_D, input_value);
    } else {
        fprintf(stderr, "Invalid IOCTL type. Use A, B, or C.\n");
        close(fd);
        return -1;
    }

    // Check IOCTL execution status
    if (ret < 0) {
        perror("Failed to execute IOCTL");
    } else {
        printf("IOCTL command executed successfully with value: %s\n", input_value);
    }

    // Close the device file
    close(fd);
    return 0;
}


#include "fm10k_eye_firmware.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int fm10k_eye_firmware_read(const char *path, uint16_t out[FM10K_EYE_MASTER_WORDS]) {
    unsigned char bytes[FM10K_EYE_MASTER_WORDS*2];
    struct stat st;
    if (!path || !out) return -1;
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) return -1;
    int rc=-1;
    if (fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid || (st.st_mode&022) ||
        st.st_size!=(off_t)sizeof(bytes)) goto done;
    size_t at=0;
    while(at<sizeof(bytes)) {
        ssize_t n=read(fd,bytes+at,sizeof(bytes)-at);
        if(n<=0) goto done;
        at+=(size_t)n;
    }
    /* Content identity and corruption check. Installation additionally pins
     * SHA-256; the root-only input and firmware CRC/version are independent
     * checks. This FNV value is not an authentication mechanism. */
    uint64_t hash=UINT64_C(0xcbf29ce484222325);
    for(size_t i=0;i<sizeof(bytes);++i) hash=(hash^bytes[i])*UINT64_C(0x100000001b3);
    if(hash!=UINT64_C(0x3bada4e60f7eb71c)) goto done;
    for(size_t i=0;i<FM10K_EYE_MASTER_WORDS;++i) {
        out[i]=(uint16_t)(bytes[i*2]|bytes[i*2+1]<<8);
        if(out[i]>1023) goto done;
    }
    rc=0;
done:
    close(fd);
    return rc;
}
